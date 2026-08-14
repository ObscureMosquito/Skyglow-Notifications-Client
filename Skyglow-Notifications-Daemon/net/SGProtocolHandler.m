#import "SGProtocolHandler.h"
#import "SGDatabaseManager.h"
#import "SGConfiguration.h"
#import "SGKeepAliveOffload.h"
#import "SGAvailability.h"
#import "SGLog.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdatomic.h>
#include <time.h>
#include <mach/mach_time.h>
#include <arpa/inet.h>

static id<SGProtocolDelegate> _delegate = nil;
static SSL *_ssl = NULL;
static SSL_CTX *_sslctx = NULL;
static int _sock = -1;
static _Atomic uint64_t _connectionGeneration = 0;
static pthread_mutex_t _sendLock = PTHREAD_MUTEX_INITIALIZER;

static pthread_rwlock_t _sslLock = PTHREAD_RWLOCK_INITIALIZER;

static pthread_mutex_t _pingLock = PTHREAD_MUTEX_INITIALIZER;

static NSString *_userAddress = nil;
static RSA      *_userPrivKey = NULL;
static int64_t   _loginTimestamp = 0;
static uint8_t   _pendingNonce[SGP_NONCE_LEN];
static BOOL      _hasPendingNonce = NO;

static uint64_t  _pingSeq = 0;
static double    _pingPendingSince = 0.0;
static int64_t   _pingPendingWallSince = 0;
static double    _lastFrameReceivedAt = 0.0;
static uint32_t  _lastRetryHint = 0;

static int64_t _clockSkewSeconds = 0;

static char     *_regPendingPrivKey = NULL;
static size_t    _regPendingPrivKeyLen = 0;
static RSA      *_regPendingRSA = NULL;
static int64_t   _regTimestamp = 0;
static pthread_mutex_t _regKeyLock = PTHREAD_MUTEX_INITIALIZER;

static void SGP_ClearPendingRegistrationKeypairLocked(void) {
    if (_regPendingRSA) {
        RSA_free(_regPendingRSA);
        _regPendingRSA = NULL;
    }
    if (_regPendingPrivKey) {
        SGP_ZeroAndFreeKeyMaterial(_regPendingPrivKey,
                                   _regPendingPrivKeyLen);
        _regPendingPrivKey = NULL;
        _regPendingPrivKeyLen = 0;
    }
}

static void SGP_ClearPendingRegistrationKeypair(void) {
    pthread_mutex_lock(&_regKeyLock);
    SGP_ClearPendingRegistrationKeypairLocked();
    pthread_mutex_unlock(&_regKeyLock);
}

static char  *_regIdentityPEM = NULL;
static size_t _regIdentityPEMLen = 0;

void SGP_SetRegistrationIdentity(NSString *identityPEM) {
    if (_regIdentityPEM) {
        SGP_ZeroAndFreeKeyMaterial(_regIdentityPEM, _regIdentityPEMLen);
        _regIdentityPEM = NULL;
        _regIdentityPEMLen = 0;
    }
    const char *utf8 = [identityPEM UTF8String];
    if (utf8 && utf8[0]) {
        _regIdentityPEMLen = strlen(utf8);
        _regIdentityPEM = malloc(_regIdentityPEMLen + 1);
        if (_regIdentityPEM) memcpy(_regIdentityPEM, utf8, _regIdentityPEMLen + 1);
        else _regIdentityPEMLen = 0;
    }
}

static BOOL SGP_LoadRegistrationIdentity(SSL_CTX *ctx) {
    BIO *b = BIO_new_mem_buf(_regIdentityPEM, (int)_regIdentityPEMLen);
    if (!b) return NO;
    X509 *leaf = PEM_read_bio_X509(b, NULL, 0, NULL);
    if (!leaf || SSL_CTX_use_certificate(ctx, leaf) != 1) {
        if (leaf) X509_free(leaf);
        BIO_free(b);
        return NO;
    }
    X509_free(leaf);
    X509 *chain;
    while ((chain = PEM_read_bio_X509(b, NULL, 0, NULL)) != NULL) {
        if (SSL_CTX_add_extra_chain_cert(ctx, chain) != 1) { X509_free(chain); break; }
    }
    ERR_clear_error();
    BIO_free(b);

    b = BIO_new_mem_buf(_regIdentityPEM, (int)_regIdentityPEMLen);
    if (!b) return NO;
    EVP_PKEY *key = PEM_read_bio_PrivateKey(b, NULL, 0, NULL);
    BIO_free(b);
    if (!key) return NO;
    int ok = (SSL_CTX_use_PrivateKey(ctx, key) == 1 && SSL_CTX_check_private_key(ctx) == 1);
    EVP_PKEY_free(key);
    return ok ? YES : NO;
}

typedef enum {
    SGPProtoPreHello       = 0,
    SGPProtoHelloReceived  = 1,
    SGPProtoChallengeWait  = 2,
    SGPProtoAuthWait       = 3,
    SGPProtoAuthenticated  = 4,
} SGPProtoPhase;

static SGPProtoPhase _phase = SGPProtoPreHello;
static BOOL _v1HelloConsumed = NO;


static double SG_GetMonotonicSeconds(void) {
    static mach_timebase_info_data_t tb;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ mach_timebase_info(&tb); });
    return (double)mach_absolute_time() * (double)tb.numer / ((double)tb.denom * 1.0e9);
}

static int64_t SG_GetCorrectedTime(void) {
    pthread_mutex_lock(&_sendLock);
    int64_t skew = _clockSkewSeconds;
    pthread_mutex_unlock(&_sendLock);
    return (int64_t)time(NULL) + skew;
}

static void SG_EncodeBE64(int64_t v, uint8_t out[8]) {
    uint64_t u = (uint64_t)v;
    out[0]=(u>>56)&0xFF; out[1]=(u>>48)&0xFF; out[2]=(u>>40)&0xFF; out[3]=(u>>32)&0xFF;
    out[4]=(u>>24)&0xFF; out[5]=(u>>16)&0xFF; out[6]=(u>> 8)&0xFF; out[7]=(u    )&0xFF;
}

static int64_t SG_DecodeBE64(const uint8_t p[8]) {
    uint64_t u = 0;
    for (int i = 0; i < 8; i++) u = (u << 8) | p[i];
    return (int64_t)u;
}

static uint32_t SG_DecodeBE32(const uint8_t p[4]) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static BOOL SG_IsAddressCharsetSafe(const uint8_t *bytes, uint16_t len) {
    if (len == 0 || len > 255) return NO;
    for (uint16_t i = 0; i < len; i++) {
        uint8_t c = bytes[i];
        BOOL ok = (c >= 'A' && c <= 'Z') ||
                  (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') ||
                  c == '.' || c == '_' || c == '@' || c == '-';
        if (!ok) return NO;
    }
    return YES;
}

const char *SGP_ErrorName(int code) {
    switch (code) {
        case SGP_OK:                   return "SGP_OK";
        case SGP_ERR_CLOSED:           return "SGP_ERR_CLOSED";
        case SGP_ERR_PROTO:            return "SGP_ERR_PROTO";
        case SGP_ERR_IO:               return "SGP_ERR_IO";
        case SGP_ERR_AUTH:             return "SGP_ERR_AUTH";
        case SGP_ERR_TIMEOUT:          return "SGP_ERR_TIMEOUT";
        case SGP_ERR_REPLACED:         return "SGP_ERR_REPLACED";
        case SGP_ERR_VERSION_MISMATCH: return "SGP_ERR_VERSION_MISMATCH";
        default:                       return "SGP_ERR_UNKNOWN";
    }
}

const char *SGP_ConnectErrorName(int code) {
    switch (code) {
        case 0:  return "SGP_CONNECT_OK";
        case -1: return "SGP_CONNECT_SOCKET_FAILED";
        case -2: return "SGP_CONNECT_IMMEDIATE_FAILED";
        case -3: return "SGP_CONNECT_SELECT_TIMEOUT";
        case -4: return "SGP_CONNECT_SOCKET_ERROR";
        case -5: return "SGP_CONNECT_INVALID_ENDPOINT";
        case -6: return "SGP_CONNECT_TLS_CONTEXT_FAILED";
        case -7: return "SGP_CONNECT_TLS_FAILED";
        case -8: return "SGP_CONNECT_PINNED_CERT_INVALID";
        case -9: return "SGP_CONNECT_NO_PEER_CERT";
        case -10: return "SGP_CONNECT_PIN_MISMATCH";
        case -11: return "SGP_CONNECT_REG_IDENTITY_INVALID";
        default: return "SGP_CONNECT_UNKNOWN";
    }
}

static int SG_WaitForSocket(int sock, int forWrite, int timeoutSec) {
    if (sock < 0 || sock >= FD_SETSIZE) return -1;
    fd_set fds; FD_ZERO(&fds); FD_SET(sock, &fds);
    struct timeval tv = {timeoutSec, 0};
    if (forWrite)
        return (select(sock + 1, NULL, &fds, NULL, &tv) > 0) ? 0 : -1;
    else
        return (select(sock + 1, &fds, NULL, NULL, &tv) > 0) ? 0 : -1;
}

static int SG_SSLReadExact(void *buf, int len) {
    if (!_ssl) return -1;
    pthread_rwlock_rdlock(&_sslLock);
    if (!_ssl) { pthread_rwlock_unlock(&_sslLock); return -1; }
    int total = 0;
    while (total < len) {
        int n = SSL_read(_ssl, (char *)buf + total, len - total);
        if (n > 0) { total += n; continue; }
        int err = SSL_get_error(_ssl, n);
        if (err == SSL_ERROR_WANT_READ) {
            if (SG_WaitForSocket(_sock, 0, 10) != 0) { pthread_rwlock_unlock(&_sslLock); return -1; }
            continue;
        }
        if (err == SSL_ERROR_WANT_WRITE) {
            if (SG_WaitForSocket(_sock, 1, 10) != 0) { pthread_rwlock_unlock(&_sslLock); return -1; }
            continue;
        }
        pthread_rwlock_unlock(&_sslLock);
        return -1;
    }
    pthread_rwlock_unlock(&_sslLock);
    return 0;
}

static int SG_SSLWriteLocked(const void *buf, int len) {
    if (!_ssl) return -1;
    pthread_rwlock_wrlock(&_sslLock);
    if (!_ssl) { pthread_rwlock_unlock(&_sslLock); return -1; }
    int total = 0;
    while (total < len) {
        int n = SSL_write(_ssl, (const char *)buf + total, len - total);
        if (n > 0) { total += n; continue; }
        int err = SSL_get_error(_ssl, n);
        if (err == SSL_ERROR_WANT_WRITE) {
            if (SG_WaitForSocket(_sock, 1, 10) != 0) { pthread_rwlock_unlock(&_sslLock); return -1; }
            continue;
        }
        if (err == SSL_ERROR_WANT_READ) {
            if (SG_WaitForSocket(_sock, 0, 10) != 0) { pthread_rwlock_unlock(&_sslLock); return -1; }
            continue;
        }
        pthread_rwlock_unlock(&_sslLock);
        return -1;
    }
    pthread_rwlock_unlock(&_sslLock);
    return 0;
}

static int SGP_LowLevelSend(SGPMsgType type, const void *payload, uint32_t len) {
    if (len > SGP_MAX_PAYLOAD_LEN) return -1;

    uint32_t frameLen = SGP_HEADER_SIZE + len;
    uint8_t *frame = malloc(frameLen);
    if (!frame) return -1;

    frame[0] = SGP_MAGIC; frame[1] = SGP_VERSION;
    frame[2] = (uint8_t)type; frame[3] = 0;
    uint32_t lenBE = htonl(len); memcpy(frame + 4, &lenBE, 4);
    if (len > 0 && payload) memcpy(frame + SGP_HEADER_SIZE, payload, len);

    pthread_mutex_lock(&_sendLock);
    int rc = SG_SSLWriteLocked(frame, (int)frameLen);
    pthread_mutex_unlock(&_sendLock);
    free(frame);
    return rc;
}

static uint8_t *SG_SignPSS(RSA *rsa, const uint8_t *d1, size_t l1, const uint8_t *d2, size_t l2, const uint8_t *d3, size_t l3, size_t *outLen) {
    *outLen = 0;
    uint8_t digest[32];
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha256(), NULL);
    if (l1) EVP_DigestUpdate(md, d1, l1);
    if (l2) EVP_DigestUpdate(md, d2, l2);
    if (l3) EVP_DigestUpdate(md, d3, l3);
    EVP_DigestFinal_ex(md, digest, NULL);
    EVP_MD_CTX_free(md);

    int size = RSA_size(rsa);
    uint8_t *em = malloc(size);
    if (!em) return NULL;

    if (RSA_padding_add_PKCS1_PSS_mgf1(rsa, em, digest, EVP_sha256(), EVP_sha256(), -1) != 1) {
        free(em);
        return NULL;
    }

    uint8_t *sig = malloc(size);
    if (!sig) { free(em); return NULL; }

    int sigLen = RSA_private_encrypt(size, em, sig, rsa, RSA_NO_PADDING);
    memset(em, 0, size);
    free(em);

    if (sigLen <= 0) {
        memset(sig, 0, size);
        free(sig);
        return NULL;
    }

    *outLen = (size_t)sigLen;
    return sig;
}

static int SG_SendChallengeResponse(SGPMsgType type, RSA *rsa, NSString *addr, int64_t ts) {
    const char *u = addr ? [addr UTF8String] : NULL;
    size_t ul = u ? strlen(u) : 0;
    uint8_t tsBE[8]; SG_EncodeBE64(ts, tsBE);
    size_t sl = 0;
    uint8_t *sig = SG_SignPSS(rsa, _pendingNonce, SGP_NONCE_LEN,
                              (const uint8_t *)u, ul, tsBE, 8, &sl);
    _hasPendingNonce = NO;
    if (!sig) return -1;

    if (sl > 512) {
        memset(sig, 0, sl);
        free(sig);
        return -1;
    }

    uint8_t p[8 + 2 + 512];
    memcpy(p, tsBE, 8);
    p[8] = (sl >> 8) & 0xFF; p[9] = sl & 0xFF;
    memcpy(p + 10, sig, sl);
    memset(sig, 0, sl);
    free(sig);
    return SGP_LowLevelSend(type, p, (uint32_t)(10 + sl));
}


void SGP_PrepareRegistrationKeypair(void) {
    pthread_mutex_lock(&_regKeyLock);
    BOOL alreadyHave = (_regPendingRSA != NULL);
    pthread_mutex_unlock(&_regKeyLock);
    if (alreadyHave) return;

    BIGNUM *bn = BN_new(); BN_set_word(bn, RSA_F4);
    RSA *rsa = RSA_new(); RSA_generate_key_ex(rsa, 2048, bn, NULL);
    BN_free(bn);

    BIO *privBio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(privBio, rsa, NULL, NULL, 0, NULL, NULL);
    long privLen = BIO_pending(privBio);
    char *privBuf = calloc((size_t)privLen + 1, 1);
    if (!privBuf) {
        BIO_free(privBio);
        RSA_free(rsa);
        return;
    }
    BIO_read(privBio, privBuf, (int)privLen);
    BIO_free(privBio);

    pthread_mutex_lock(&_regKeyLock);
    if (_regPendingRSA) {
        pthread_mutex_unlock(&_regKeyLock);
        SGP_ZeroAndFreeKeyMaterial(privBuf, (size_t)privLen);
        RSA_free(rsa);
        return;
    }
    _regPendingPrivKey    = privBuf;
    _regPendingPrivKeyLen = (size_t)privLen;
    _regPendingRSA        = rsa;
    pthread_mutex_unlock(&_regKeyLock);
    SGLOGI(SGProtocolHandler, "code=%s result=ready", SGND_REGISTRATION_KEY_PREPARED);
}

BOOL SGP_BeginFirstTimeRegistration(void) {
    if (!SGP_IsConnected()) return NO;

    SGP_PrepareRegistrationKeypair();

    pthread_mutex_lock(&_regKeyLock);
    RSA *rsa = _regPendingRSA;
    pthread_mutex_unlock(&_regKeyLock);
    if (!rsa) return NO;

    uint8_t *pubDer = NULL;
    int pubDerLen = i2d_RSA_PUBKEY(rsa, &pubDer);

    _regTimestamp = SG_GetCorrectedTime();
    uint8_t tsBE[8]; SG_EncodeBE64(_regTimestamp, tsBE);

    NSMutableData *payload = [NSMutableData data];
    uint8_t keyLenBE[2] = {(uint8_t)(pubDerLen >> 8), (uint8_t)(pubDerLen & 0xFF)};
    [payload appendBytes:keyLenBE length:2];
    [payload appendBytes:pubDer length:pubDerLen];
    [payload appendBytes:tsBE length:8];
    uint32_t ver = htonl(SGP_VERSION); [payload appendBytes:&ver length:4];

    OPENSSL_free(pubDer);

    _phase = SGPProtoChallengeWait;
    SGP_LowLevelSend(SGP_C_REGISTER, [payload bytes], (uint32_t)[payload length]);
    return YES;
}

void SGP_ZeroAndFreeKeyMaterial(char *pemBuf, size_t len) {
    if (!pemBuf) return;
    volatile char *vp = pemBuf;
    for (size_t i = 0; i < len; i++) vp[i] = 0;
    free(pemBuf);
}

void SGP_SetDelegate(id<SGProtocolDelegate> delegate) { _delegate = delegate; }
BOOL SGP_IsConnected(void) { return (_ssl != NULL && _sock >= 0); }
uint64_t SGP_GetConnectionGeneration(void) { return atomic_load(&_connectionGeneration); }

int SGP_GetSocketFD(void) { return _sock; }
uint32_t SGP_GetLastDisconnectRetryAfter(void) { return _lastRetryHint; }
double SGP_GetLastFrameReceivedAt(void) { return _lastFrameReceivedAt; }

BOOL SGP_SendKeepAlivePing(void) {
    if (!SGP_IsConnected()) return NO;

    pthread_mutex_lock(&_pingLock);
    if (_pingPendingSince > 0.0) {
        pthread_mutex_unlock(&_pingLock);
        return NO;
    }
    _pingSeq++;
    _pingPendingSince = SG_GetMonotonicSeconds();
    _pingPendingWallSince = (int64_t)time(NULL);
    uint8_t seq[8];
    SG_EncodeBE64((int64_t)_pingSeq, seq);
    pthread_mutex_unlock(&_pingLock);

    if (SGP_LowLevelSend(SGP_C_PING, seq, 8) != 0) {
        pthread_mutex_lock(&_pingLock);
        _pingPendingSince = 0.0;
        _pingPendingWallSince = 0;
        pthread_mutex_unlock(&_pingLock);
        return NO;
    }
    return YES;
}

double SGP_GetPendingPingAgeWallSeconds(void) {
    pthread_mutex_lock(&_pingLock);
    int64_t since = _pingPendingWallSince;
    pthread_mutex_unlock(&_pingLock);
    if (since <= 0) return 0.0;
    double age = difftime(time(NULL), (time_t)since);
    return (age > 0.0) ? age : 0.0;
}

void SGP_AbortConnection(void) {
    int s = _sock;
    _sock = -1;
    if (s >= 0) {
        shutdown(s, SHUT_RDWR);
        close(s);
    }
}

void SGP_DisconnectFromServer(void) {
    if (_userPrivKey) { RSA_free(_userPrivKey); _userPrivKey = NULL; }

    pthread_rwlock_wrlock(&_sslLock);
    if (_ssl) { SSL_shutdown(_ssl); SSL_free(_ssl); _ssl = NULL; }
    pthread_rwlock_unlock(&_sslLock);

    if (_sslctx) { SSL_CTX_free(_sslctx); _sslctx = NULL; }
    if (_sock >= 0) { close(_sock); _sock = -1; }
    [_userAddress release]; _userAddress = nil;
    pthread_mutex_lock(&_regKeyLock);
    SGP_ClearPendingRegistrationKeypairLocked();
    pthread_mutex_unlock(&_regKeyLock);
    pthread_mutex_lock(&_pingLock);
    _pingPendingSince = 0.0;
    _pingPendingWallSince = 0;
    pthread_mutex_unlock(&_pingLock);
    _lastFrameReceivedAt = 0.0;
    _phase = SGPProtoPreHello;
    _v1HelloConsumed = NO;
    SGKAOffload_Reset();
}

static _Atomic int _lastConnectOSError = 0;

int SGP_GetLastConnectOSError(void) {
    return atomic_load(&_lastConnectOSError);
}

int SGP_ConnectToServer(const char *ip, int port, NSString *pinnedCert) {
    signal(SIGPIPE, SIG_IGN);
    atomic_fetch_add(&_connectionGeneration, 1);
    SGP_DisconnectFromServer();
    atomic_store(&_lastConnectOSError, 0);
    _lastRetryHint = 0;
    _lastFrameReceivedAt = 0.0;

    struct sockaddr_storage peerAddress;
    memset(&peerAddress, 0, sizeof(peerAddress));
    socklen_t peerAddressLength = 0;
    int addressFamily = AF_UNSPEC;

    if (ip && port > 0 && port <= UINT16_MAX) {
        struct sockaddr_in *address4 = (struct sockaddr_in *)&peerAddress;
        if (inet_pton(AF_INET, ip, &address4->sin_addr) == 1) {
            addressFamily = AF_INET;
            address4->sin_len = sizeof(*address4);
            address4->sin_family = AF_INET;
            address4->sin_port = htons((uint16_t)port);
            peerAddressLength = sizeof(*address4);
        } else {
            struct sockaddr_in6 *address6 = (struct sockaddr_in6 *)&peerAddress;
            if (inet_pton(AF_INET6, ip, &address6->sin6_addr) == 1) {
                addressFamily = AF_INET6;
                address6->sin6_len = sizeof(*address6);
                address6->sin6_family = AF_INET6;
                address6->sin6_port = htons((uint16_t)port);
                peerAddressLength = sizeof(*address6);
            }
        }
    }

    if (addressFamily == AF_UNSPEC) return -5;

    _sslctx = SSL_CTX_new(TLS_client_method());
    if (!_sslctx) return -6;
    SSL_CTX_set_options(_sslctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    SSL_CTX_set_verify(_sslctx, SSL_VERIFY_NONE, NULL);

    if (_regIdentityPEM && !SGP_LoadRegistrationIdentity(_sslctx)) {
        SGLOGE(SGP, "code=%s result=failed reason=registration_identity_invalid", SGND_PROTOCOL_CONNECT_CERT_FAILED);
        SGP_DisconnectFromServer();
        return -11;
    }

    _sock = socket(addressFamily, SOCK_STREAM, 0);
    if (_sock < 0) {
        atomic_store(&_lastConnectOSError, errno);
        SGP_DisconnectFromServer();
        return -1;
    }

    int yes = 1;
    setsockopt(_sock, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

    int flags = fcntl(_sock, F_GETFL, 0);
    fcntl(_sock, F_SETFL, flags | O_NONBLOCK);

    int connectResult = connect(_sock, (struct sockaddr *)&peerAddress, peerAddressLength);
    if (connectResult < 0 && errno != EINPROGRESS) {
        atomic_store(&_lastConnectOSError, errno);
        SGP_DisconnectFromServer();
        return -2;
    }

    if (connectResult < 0) {
        if (_sock >= FD_SETSIZE) { SGP_DisconnectFromServer(); return -3; }
        fd_set wfds; FD_ZERO(&wfds); FD_SET(_sock, &wfds);
        struct timeval tv = {SGP_NET_OP_TIMEOUT_SEC, 0};
        int sel = select(_sock + 1, NULL, &wfds, NULL, &tv);
        if (sel <= 0) {
            atomic_store(&_lastConnectOSError, (sel == 0) ? ETIMEDOUT : errno);
            SGP_DisconnectFromServer();
            return -3;
        }

        int sockErr = 0; socklen_t errLen = sizeof(sockErr);
        getsockopt(_sock, SOL_SOCKET, SO_ERROR, &sockErr, &errLen);
        if (sockErr != 0) {
            atomic_store(&_lastConnectOSError, sockErr);
            SGP_DisconnectFromServer();
            return -4;
        }
    }

    fcntl(_sock, F_SETFL, flags);

    struct timeval timeout;
    timeout.tv_sec = SGP_NET_OP_TIMEOUT_SEC;
    timeout.tv_usec = 0;
    setsockopt(_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    unsigned char *pinnedDer = NULL;
    int pinnedDerLen = 0;
    {
        const char *utf8Cert = [pinnedCert UTF8String];
        BIO *b = utf8Cert ? BIO_new_mem_buf((void *)utf8Cert, (int)strlen(utf8Cert)) : NULL;
        X509 *pinnedX = b ? PEM_read_bio_X509(b, NULL, 0, NULL) : NULL;
        if (b) BIO_free(b);
        if (!pinnedX) {
            SGLOGE(SGP, "code=%s result=failed reason=pem_read_x509", SGND_PROTOCOL_CONNECT_CERT_FAILED);
            unsigned long openSslErr;
            while ((openSslErr = ERR_get_error()) != 0) {
                char errBuf[256];
                ERR_error_string_n(openSslErr, errBuf, sizeof(errBuf));
                SGLOGE(SGP, "code=%s reason=%s", SGND_PROTOCOL_OPENSSL_ERROR, errBuf);
            }
            SGP_DisconnectFromServer();
            return -8;
        }
        pinnedDerLen = i2d_X509(pinnedX, &pinnedDer);
        X509_free(pinnedX);
        if (pinnedDerLen <= 0 || !pinnedDer) {
            if (pinnedDer) OPENSSL_free(pinnedDer);
            SGP_DisconnectFromServer();
            return -8;
        }
    }

    _ssl = SSL_new(_sslctx);
    if (!_ssl) { OPENSSL_free(pinnedDer); SGP_DisconnectFromServer(); return -6; }
    SSL_set_fd(_ssl, _sock);
    if (SSL_connect(_ssl) != 1) { OPENSSL_free(pinnedDer); SGP_DisconnectFromServer(); return -7; }

    X509 *peer = SSL_get_peer_certificate(_ssl);
    if (!peer) {
        OPENSSL_free(pinnedDer);
        SGLOGE(SGP, "code=%s result=failed reason=no_peer_cert", SGND_PROTOCOL_CONNECT_CERT_FAILED);
        SGP_DisconnectFromServer();
        return -9;
    }
    unsigned char *peerDer = NULL;
    int peerDerLen = i2d_X509(peer, &peerDer);
    X509_free(peer);
    BOOL pinMatch = (peerDer && peerDerLen == pinnedDerLen &&
                     memcmp(peerDer, pinnedDer, (size_t)pinnedDerLen) == 0);
    if (peerDer) OPENSSL_free(peerDer);
    OPENSSL_free(pinnedDer);
    if (!pinMatch) {
        SGLOGE(SGP, "code=%s result=failed reason=pin_mismatch", SGND_PROTOCOL_CONNECT_CERT_FAILED);
        SGP_DisconnectFromServer();
        return -10;
    }

    return 0;
}

void SGP_BeginLoginHandshake(NSString *address, RSA *privKey) {
    _userAddress = [address retain];
    _userPrivKey = privKey;
    _loginTimestamp = SG_GetCorrectedTime();

    const char *u = [address UTF8String]; uint16_t ul = (uint16_t)strlen(u);
    NSMutableData *p = [NSMutableData data];
    uint8_t ulBE[2] = {(uint8_t)(ul >> 8), (uint8_t)(ul & 0xFF)};
    [p appendBytes:ulBE length:2];
    [p appendBytes:u length:ul];
    uint8_t tsBE[8]; SG_EncodeBE64(_loginTimestamp, tsBE);
    [p appendBytes:tsBE length:8];
    uint32_t v = htonl(SGP_VERSION); [p appendBytes:&v length:4];

    _phase = SGPProtoChallengeWait;
    SGP_LowLevelSend(SGP_C_LOGIN, [p bytes], (uint32_t)[p length]);
}

void SGP_EnqueueAcknowledgement(NSData *msgID, int status) {
    if (!msgID || [msgID length] != 16) return;

    uint8_t p[17];
    memcpy(p, [msgID bytes], 16);
    p[16] = (uint8_t)status;

    if (SGP_IsConnected() && SGP_LowLevelSend(SGP_C_ACK, p, 17) == 0) return;

    [[SGDatabaseManager sharedManager] enqueueAcknowledgementForMessageID:msgID status:status];
}

void SGP_FlushPendingAcknowledgements(void) {
    if (!SGP_IsConnected()) return;
    NSArray *pending = [[SGDatabaseManager sharedManager] pendingAcknowledgements];
    for (NSDictionary *ack in pending) {
        uint8_t p[17];
        memcpy(p, [ack[@"msgID"] bytes], 16);
        p[16] = (uint8_t)[ack[@"status"] intValue];
        if (SGP_LowLevelSend(SGP_C_ACK, p, 17) == 0) {
            [[SGDatabaseManager sharedManager] removeAcknowledgementForMessageID:ack[@"msgID"]];
        } else break;
    }
}

void SGP_FlushActiveTopicFilter(void) {
    if (!SGP_IsConnected()) return;

    NSArray *entries = [[SGDatabaseManager sharedManager] allBundleRegistrations];
    NSUInteger total = [entries count];

    NSUInteger i = 0;
    while (i < total || total == 0) {
        NSMutableData *body = [NSMutableData data];
        uint16_t count = 0;
        const NSUInteger maxBody = SGP_MAX_PAYLOAD_LEN - 3;

        while (i < total) {
            NSDictionary *e   = entries[i];
            NSData       *rk  = e[@"routingKey"];
            NSString     *bid = e[@"bundleID"];
            BOOL          mut = [e[@"isMuted"] boolValue];
            if ([rk length] != SGP_ROUTING_KEY_LEN || ![bid length]) { i++; continue; }

            const char *bidC = [bid UTF8String];
            NSUInteger  blen = strlen(bidC);
            if (blen > 0xFFFF) { i++; continue; }

            NSUInteger entrySize = 1 + SGP_ROUTING_KEY_LEN + 2 + blen;
            if ([body length] + entrySize > maxBody) break;
            if (count == 0xFFFF) break;

            uint8_t tag = mut ? 0x02 : 0x01;
            [body appendBytes:&tag length:1];
            [body appendData:rk];
            uint8_t blBE[2] = {(uint8_t)(blen >> 8), (uint8_t)(blen & 0xFF)};
            [body appendBytes:blBE length:2];
            [body appendBytes:bidC length:blen];

            count++;
            i++;
        }

        BOOL hasMore = (i < total);
        NSMutableData *frame = [NSMutableData dataWithCapacity:3 + [body length]];
        uint8_t flags = hasMore ? 1 : 0; [frame appendBytes:&flags length:1];
        uint8_t cBE[2] = {(uint8_t)(count >> 8), (uint8_t)(count & 0xFF)}; [frame appendBytes:cBE length:2];
        [frame appendData:body];

        if (SGP_LowLevelSend(SGP_C_FILTER, [frame bytes], (uint32_t)[frame length]) != 0) return;

        if (total == 0) return;
    }
}

BOOL SGP_SendClientDisconnect(void) {
    if (!SGP_IsConnected()) return NO;
    uint8_t reason = SGP_DISC_NORMAL;
    return SGP_LowLevelSend(SGP_C_DISCONNECT, &reason, 1) == 0;
}

int SGP_ProcessNextIncomingMessage(double pingIntervalSec) {
    if (!SGP_IsConnected()) return SGP_ERR_IO;

    int hasPending = (_ssl && SSL_pending(_ssl) > 0);

    if (!hasPending) {
        if (_sock >= FD_SETSIZE) return SGP_ERR_IO;
        fd_set rfds; FD_ZERO(&rfds); FD_SET(_sock, &rfds);
    
        struct timeval tv = {(long)pingIntervalSec, 0};
        struct timeval *tv_ptr = (pingIntervalSec > 0.0) ? &tv : NULL;

        pthread_mutex_lock(&_pingLock);
        double pendingSince = _pingPendingSince;
        pthread_mutex_unlock(&_pingLock);

        if (pendingSince > 0.0) {
            double elapsed = SG_GetMonotonicSeconds() - pendingSince;
            if (elapsed >= (double)SGP_PONG_TIMEOUT_SEC) return SGP_ERR_TIMEOUT;
            tv.tv_sec = (long)(SGP_PONG_TIMEOUT_SEC - elapsed);
            tv_ptr = &tv;
        }

        int sel = select(_sock + 1, &rfds, NULL, NULL, tv_ptr);
        if (sel < 0) return (errno == EINTR) ? SGP_OK : SGP_ERR_IO;
    
        if (sel == 0) {
            pthread_mutex_lock(&_pingLock);
            double pendingAtTimeout = _pingPendingSince;
            pthread_mutex_unlock(&_pingLock);

            if (pendingAtTimeout > 0.0) {
                double elapsed = SG_GetMonotonicSeconds() - pendingAtTimeout;
                return (elapsed >= (double)SGP_PONG_TIMEOUT_SEC) ? SGP_ERR_TIMEOUT : SGP_OK;
            }

            if (pingIntervalSec <= 0.0) return SGP_OK;

            pthread_mutex_lock(&_pingLock);
            if (_pingPendingSince > 0.0) {
                pthread_mutex_unlock(&_pingLock);
                return SGP_OK;
            }
            _pingSeq++;
            _pingPendingSince = SG_GetMonotonicSeconds();
            _pingPendingWallSince = (int64_t)time(NULL);
            uint8_t seq[8];
            SG_EncodeBE64((int64_t)_pingSeq, seq);
            pthread_mutex_unlock(&_pingLock);
            SGP_LowLevelSend(SGP_C_PING, seq, 8);
            return SGP_OK;
        }
    }

    uint8_t hdr[8];
    if (SG_SSLReadExact(hdr, 8) != 0) return SGP_ERR_IO;
    _lastFrameReceivedAt = SG_GetMonotonicSeconds();

    if (_phase == SGPProtoPreHello && !_v1HelloConsumed && hdr[0] != SGP_MAGIC) {
        uint32_t v1Len = SG_DecodeBE32(hdr);
        if (v1Len >= 12 && v1Len <= SGP_MAX_PAYLOAD_LEN && memcmp(hdr + 4, "bpli", 4) == 0) {
            uint32_t remaining = v1Len - 4;
            uint8_t *v1Body = malloc(remaining);
            if (!v1Body) return SGP_ERR_IO;
            if (SG_SSLReadExact(v1Body, (int)remaining) != 0) { free(v1Body); return SGP_ERR_IO; }
            BOOL plistMagicOK = (memcmp(v1Body, "st00", 4) == 0);
            free(v1Body);
            if (!plistMagicOK) {
                SGLOGW(SGP, "code=%s bytes=%u result=reject reason=plist_magic", SGND_PROTOCOL_V1_COMPAT_HELLO, v1Len);
                return SGP_ERR_PROTO;
            }
            _v1HelloConsumed = YES;
            SGLOGI(SGP, "code=%s bytes=%u action=upgrade_to_v2", SGND_PROTOCOL_V1_COMPAT_HELLO, v1Len);
            if (SGP_LowLevelSend(SGP_C_UPGRADE, NULL, 0) != 0) return SGP_ERR_IO;
            return SGP_OK;
        }
    }

    if (hdr[0] != SGP_MAGIC || hdr[1] != SGP_VERSION) {
        SGLOGW(SGP, "code=%s magic=0x%02X version=0x%02X expected_magic=0x%02X expected_version=0x%02X result=reject", SGND_PROTOCOL_FRAME_MAGIC_INVALID,
                    hdr[0], hdr[1], SGP_MAGIC, SGP_VERSION);
        return SGP_ERR_PROTO;
    }

    if (hdr[3] != 0x00) {
        SGLOGW(SGP, "code=%s reserved=0x%02X result=reject", SGND_PROTOCOL_FRAME_RESERVED_INVALID, hdr[3]);
        return SGP_ERR_PROTO;
    }

    uint32_t len = SG_DecodeBE32(hdr + 4);
    SGPMsgType type = (SGPMsgType)hdr[2];

    if (len > SGP_MAX_PAYLOAD_LEN) return SGP_ERR_PROTO;

    {
        typedef struct { uint32_t min; uint32_t max; } SGPBounds;
        static const SGPBounds kServerBounds[256] = {
            [SGP_S_HELLO]         = {  4,   4 },
            [SGP_S_CHALLENGE]     = { 32,  32 },
            [SGP_S_AUTH_OK]       = {  0,   0 },
            [SGP_S_NOTIFY]        = { 70,  SGP_MAX_PAYLOAD_LEN },
            [SGP_S_DISCONNECT]    = {  1,   5 },
            [SGP_S_PONG]          = {  8,   8 },
            [SGP_S_POLL_DONE]     = {  0,   0 },
            [SGP_S_REGISTER_OK]   = {  7, 261 },
            [SGP_S_REGISTER_FAIL] = {  1, 258 },
            [SGP_S_PING]          = {  8,   8 },
            [SGP_S_TIME_SYNC]     = {  8,   8 },
        };

        uint8_t idx = (uint8_t)type;
        static const uint32_t kRegisteredMask =
            (1u << SGP_S_HELLO)         | (1u << SGP_S_CHALLENGE)    |
            (1u << SGP_S_AUTH_OK)       | (1u << SGP_S_NOTIFY)       |
            (1u << SGP_S_DISCONNECT)    |
            (1u << SGP_S_PONG)          | (1u << SGP_S_POLL_DONE)    |
            (1u << SGP_S_REGISTER_OK)   | (1u << SGP_S_REGISTER_FAIL)|
            (1u << SGP_S_PING)          | (1u << SGP_S_TIME_SYNC);

        if (idx < 32 && (kRegisteredMask & (1u << idx))) {
            if (len < kServerBounds[idx].min || len > kServerBounds[idx].max) {
                SGLOGW(SGP, "code=%s type=0x%02X bytes=%u min=%u max=%u result=reject", SGND_PROTOCOL_FRAME_SIZE_INVALID,
                            idx, len, kServerBounds[idx].min, kServerBounds[idx].max);
                return SGP_ERR_PROTO;
            }
        }
    }

    int result = SGP_OK;
    uint32_t rxAssertion = 0;
    uint8_t *raw = NULL;
    if (len > 0) {
        rxAssertion = [[SGAvailability shared]
            createTimedPowerAssertionWithName:@"com.skyglow.sgn.receive"
                                      timeout:SG_POWER_ASSERTION_TIMEOUT_SEC];
        raw = malloc(len);
        if (!raw) { result = SGP_ERR_IO; goto cleanup; }
        if (SG_SSLReadExact(raw, (int)len) != 0) { result = SGP_ERR_IO; goto cleanup; }
    }

    switch (type) {
        case SGP_S_NOTIFY:
        case SGP_S_AUTH_OK:
        case SGP_S_POLL_DONE:
            pthread_mutex_lock(&_pingLock);
            _pingPendingSince = 0.0;
            _pingPendingWallSince = 0;
            pthread_mutex_unlock(&_pingLock);
            break;
        default:
            break;
    }

    switch (type) {
        case SGP_S_HELLO: {
            if (_phase != SGPProtoPreHello) {
                SGLOGW(SGP, "code=%s type=S_HELLO phase=%d result=unsolicited",
                       SGND_PROTOCOL_FRAME_SIZE_INVALID, (int)_phase);
                result = SGP_ERR_PROTO; goto cleanup;
            }
            _phase = SGPProtoHelloReceived;
            [_delegate protocolDidReceiveWelcomeChallenge];
            break;
        }
        case SGP_S_CHALLENGE: {
            if (_phase != SGPProtoChallengeWait) {
                SGLOGW(SGP, "code=%s type=S_CHALLENGE phase=%d result=unsolicited",
                       SGND_PROTOCOL_FRAME_SIZE_INVALID, (int)_phase);
                result = SGP_ERR_PROTO; goto cleanup;
            }
            if (len < SGP_NONCE_LEN) { result = SGP_ERR_PROTO; goto cleanup; }
            memcpy(_pendingNonce, raw, SGP_NONCE_LEN); _hasPendingNonce = YES;
            _phase = SGPProtoAuthWait;

            if (_regPendingRSA) SG_SendChallengeResponse(SGP_C_REGISTER_RESP, _regPendingRSA, nil, _regTimestamp);
            else                SG_SendChallengeResponse(SGP_C_LOGIN_RESP, _userPrivKey, _userAddress, _loginTimestamp);
            break;
        }
        case SGP_S_AUTH_OK: {
            /* Only valid after we sent C_LOGIN_RESP */
            if (_phase != SGPProtoAuthWait || _regPendingRSA != NULL) {
                SGLOGW(SGP, "code=%s type=S_AUTH_OK phase=%d result=unsolicited",
                       SGND_PROTOCOL_FRAME_SIZE_INVALID, (int)_phase);
                result = SGP_ERR_PROTO; goto cleanup;
            }
            _phase = SGPProtoAuthenticated;
            [_delegate protocolDidAuthenticateSuccessfully];
            break;
        }
        case SGP_S_NOTIFY: {
            if (_phase != SGPProtoAuthenticated) {
                SGLOGW(SGP, "code=%s type=S_NOTIFY phase=%d result=unsolicited",
                       SGND_PROTOCOL_FRAME_SIZE_INVALID, (int)_phase);
                result = SGP_ERR_PROTO; goto cleanup;
            }
            if (len < SGP_NOTIFY_MIN_PAYLOAD) { result = SGP_ERR_PROTO; goto cleanup; }

            NSData *rk  = [NSData dataWithBytes:raw length:SGP_ROUTING_KEY_LEN];
            NSData *mid = [NSData dataWithBytes:raw + SGP_ROUTING_KEY_LEN length:SGP_MSG_ID_LEN];
            int64_t deviceSeq = SG_DecodeBE64(raw + SGP_NOTIFY_OFF_SEQ);
            int64_t expiresAt = SG_DecodeBE64(raw + SGP_NOTIFY_OFF_EXPIRES_AT);
            uint32_t dl = SG_DecodeBE32(raw + SGP_NOTIFY_OFF_DATA_LEN);

            if ((uint64_t)SGP_NOTIFY_MIN_PAYLOAD + dl > (uint64_t)len) {
                SGLOGW(SGP, "code=%s data_len=%u frame_len=%u result=reject", SGND_PROTOCOL_NOTIFY_BOUNDS_INVALID, dl, len);
                result = SGP_ERR_PROTO; goto cleanup;
            }

            uint8_t notifFlags = raw[SGP_NOTIFY_OFF_FLAGS];
            NSMutableDictionary *notif = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                rk,  @"routing_key",
                mid, @"msg_id",
                @((notifFlags & SGP_NOTIFY_FLAG_ENCRYPTED)  != 0), @"is_encrypted",
                @((notifFlags & SGP_NOTIFY_FLAG_COMPRESSED) != 0), @"is_compressed",
                @(raw[SGP_NOTIFY_OFF_CONTENT_TYPE]), @"content_type",
                @(deviceSeq), @"device_seq",
                nil];
            notif[@"data"] = [NSData dataWithBytes:raw + SGP_NOTIFY_MIN_PAYLOAD length:dl];
            if (expiresAt > 0) notif[@"expires_at"] = @(expiresAt);

            if (notifFlags & SGP_NOTIFY_FLAG_ENCRYPTED) {
                if ((uint64_t)SGP_NOTIFY_MIN_PAYLOAD + dl + SGP_GCM_IV_LEN > (uint64_t)len) {
                    result = SGP_ERR_PROTO; goto cleanup;
                }
                notif[@"iv"] = [NSData dataWithBytes:raw + SGP_NOTIFY_MIN_PAYLOAD + dl length:SGP_GCM_IV_LEN];
            }
            [_delegate protocolDidReceiveNotification:notif];
            break;
        }
        case SGP_S_DISCONNECT: {
            uint8_t reason = raw[0];
            _lastRetryHint = (len >= 5) ? SG_DecodeBE32(raw + 1) : 0;
            if (reason == SGP_DISC_AUTH_FAIL)        { result = SGP_ERR_AUTH;             goto cleanup; }
            if (reason == SGP_DISC_REPLACED)         { result = SGP_ERR_REPLACED;         goto cleanup; }
            if (reason == SGP_DISC_VERSION_MISMATCH) { result = SGP_ERR_VERSION_MISMATCH; goto cleanup; }
            result = SGP_ERR_CLOSED; goto cleanup;
        }
        case SGP_S_REGISTER_OK: {
            if (!_regPendingRSA || _phase != SGPProtoAuthWait) {
                SGLOGW(SGP, "code=%s type=S_REGISTER_OK phase=%d hasRegister=%d result=unsolicited",
                       SGND_PROTOCOL_FRAME_SIZE_INVALID, (int)_phase, _regPendingRSA != NULL);
                result = SGP_ERR_PROTO;
                goto cleanup;
            }

            uint32_t serverVer = SG_DecodeBE32(raw);
            uint16_t addrLen   = ((uint16_t)raw[4] << 8) | (uint16_t)raw[5];
            
            if (addrLen == 0 || addrLen > 255 || (uint64_t)6 + addrLen > (uint64_t)len) {
                SGLOGE(SGP, "code=%s field=address addrLen=%u frameLen=%llu result=rejected",
                       SGND_PROTOCOL_FRAME_SIZE_INVALID, addrLen, (unsigned long long)len);
                SGP_ClearPendingRegistrationKeypair();
                result = SGP_ERR_PROTO;
                goto cleanup;
            }
            /* Charset Whitelist */
            if (!SG_IsAddressCharsetSafe(raw + 6, addrLen)) {
                SGLOGE(SGP, "code=%s field=address result=rejected_charset",
                       SGND_PROTOCOL_FRAME_SIZE_INVALID);
                SGP_ClearPendingRegistrationKeypair();
                result = SGP_ERR_PROTO;
                goto cleanup;
            }
            NSString *capturedAddress = [[[NSString alloc] initWithBytes:raw + 6
                                                                  length:addrLen
                                                                encoding:NSUTF8StringEncoding] autorelease];
            pthread_mutex_lock(&_regKeyLock);
            char   *capturedPemKey = _regPendingPrivKey;
            RSA    *capturedRSA    = _regPendingRSA;
            _regPendingPrivKey    = NULL;
            _regPendingPrivKeyLen = 0;
            _regPendingRSA        = NULL;
            pthread_mutex_unlock(&_regKeyLock);
            RSA_free(capturedRSA);
            [_delegate protocolDidCompleteRegistrationWithAddress:capturedAddress
                                                       privateKey:capturedPemKey
                                                    serverVersion:serverVer];
            break;
        }
        case SGP_S_REGISTER_FAIL: {
            if (!_regPendingRSA ||
                (_phase != SGPProtoAuthWait && _phase != SGPProtoChallengeWait)) {
                SGLOGW(SGP, "code=%s type=S_REGISTER_FAIL phase=%d hasRegister=%d result=unsolicited",
                       SGND_PROTOCOL_FRAME_SIZE_INVALID, (int)_phase, _regPendingRSA != NULL);
                result = SGP_ERR_PROTO;
                goto cleanup;
            }
            uint8_t code = raw[0];
            NSString *reason = nil;
            if (len >= 4) {
                uint16_t rl = ((uint16_t)raw[1] << 8) | (uint16_t)raw[2];
                if ((uint64_t)3 + rl <= (uint64_t)len) {
                    reason = [[[NSString alloc] initWithBytes:raw + 3
                                                       length:rl
                                                     encoding:NSUTF8StringEncoding] autorelease];
                }
            }
            if (!reason) reason = @"Unknown";
            SGLOGE(SGP, "code=%s server_code=%u reason=%s result=rejected", SGND_PROTOCOL_REGISTRATION_REJECTED, code, [reason UTF8String]);
            SGP_ClearPendingRegistrationKeypair();
            [_delegate protocolDidFailRegistrationWithCode:code reason:reason];
            break;
        }
        case SGP_S_PONG: {
            /* Keep-alive only runs on an authenticated connection: the ping
             * timer arms on entry to Connected, and the pre-auth phases are
             * torn down by their own watchdogs long before a ping is due. */
            if (_phase != SGPProtoAuthenticated) {
                SGLOGW(SGP, "code=%s type=S_PONG phase=%d result=unsolicited",
                       SGND_PROTOCOL_FRAME_SIZE_INVALID, (int)_phase);
                result = SGP_ERR_PROTO; goto cleanup;
            }
            pthread_mutex_lock(&_pingLock);
            uint64_t seq = _pingSeq;
            BOOL pingWasPending = (_pingPendingSince > 0.0);
            BOOL sequenceMatches = (SG_DecodeBE64(raw) == (int64_t)seq);
            if (pingWasPending && sequenceMatches) {
                _pingPendingSince = 0.0;
                _pingPendingWallSince = 0;
            }
            pthread_mutex_unlock(&_pingLock);
            if (pingWasPending && sequenceMatches) {
                [_delegate protocolDidReceiveKeepAlivePong];
            } else {
                SGLOGW(SGP, "code=%s received=%lld expected=%llu pending=%s action=ignore",
                       SGND_KEEPALIVE_PONG_STALE, SG_DecodeBE64(raw),
                       (unsigned long long)seq, pingWasPending ? "yes" : "no");
            }
            break;
        }
        case SGP_S_PING: {
            /* Never echo for an unauthenticated peer. */
            if (_phase != SGPProtoAuthenticated) {
                SGLOGW(SGP, "code=%s type=S_PING phase=%d result=unsolicited",
                       SGND_PROTOCOL_FRAME_SIZE_INVALID, (int)_phase);
                result = SGP_ERR_PROTO; goto cleanup;
            }
            SGP_LowLevelSend(SGP_C_PONG, raw, len);
            break;
        }
        case SGP_S_POLL_DONE: {
            if (_phase != SGPProtoAuthenticated) {
                SGLOGW(SGP, "code=%s type=S_POLL_DONE phase=%d result=unsolicited",
                       SGND_PROTOCOL_FRAME_SIZE_INVALID, (int)_phase);
                result = SGP_ERR_PROTO; goto cleanup;
            }
            [_delegate protocolDidFinishOfflineQueueDrain];
            break;
        }
        case SGP_S_TIME_SYNC: {
            /* Only honour clock-skew updates from an authenticated server. */
            if (_phase != SGPProtoAuthenticated) {
                SGLOGW(SGP, "code=%s type=S_TIME_SYNC phase=%d result=unsolicited",
                       SGND_PROTOCOL_FRAME_SIZE_INVALID, (int)_phase);
                result = SGP_ERR_PROTO; goto cleanup;
            }
            int64_t serverTime = SG_DecodeBE64(raw);
            int64_t localTime  = (int64_t)time(NULL);
            int64_t offset     = serverTime - localTime;

            if (offset > 172800 || offset < -172800) {
                SGLOGW(SGP, "code=%s offset=%llds result=rejected_excessive_skew",
                       SGND_PROTOCOL_TIME_SYNC, offset);
                result = SGP_ERR_PROTO; goto cleanup;
            }
            pthread_mutex_lock(&_sendLock);
            _clockSkewSeconds = offset;
            pthread_mutex_unlock(&_sendLock);
            SGLOGI(SGP, "code=%s server=%lld local=%lld offset=%llds action=apply_skew", SGND_PROTOCOL_TIME_SYNC,
                        serverTime, localTime, offset);
            [_delegate protocolDidReceiveTimeSyncWithOffset:offset];
            break;
        }
        default: break;
    }

cleanup:
    if (rxAssertion) [[SGAvailability shared] releasePowerAssertion:rxAssertion];
    free(raw);
    return result;
}

void SGP_RequestOfflineMessages(void) {
    if (!SGP_IsConnected()) return;
    int64_t lastDeliveredSeq = [[SGDatabaseManager sharedManager] lastDeliveredSeq];
    uint8_t seqBE[8];
    SG_EncodeBE64(lastDeliveredSeq, seqBE);
    SGP_LowLevelSend(SGP_C_POLL, seqBE, 8);
}
