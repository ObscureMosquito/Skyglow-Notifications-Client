#import "SGProtocolHandler.h"
#import "SGDatabaseManager.h"
#import "SGConfiguration.h"
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
#include <time.h>
#include <mach/mach_time.h>
#include <arpa/inet.h>

static id<SGProtocolDelegate> _delegate = nil;
static SSL *_ssl = NULL;
static SSL_CTX *_sslctx = NULL;
static int _sock = -1;
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
static double    _lastFrameReceivedAt = 0.0;
static uint32_t  _lastRetryHint = 0;

static int64_t _clockSkewSeconds = 0;

static NSString *_regPendingAddress = nil;
static char     *_regPendingPrivKey = NULL;
static size_t    _regPendingPrivKeyLen = 0;
static RSA      *_regPendingRSA = NULL;
static int64_t   _regTimestamp = 0;


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
    const char *u = [addr UTF8String]; size_t ul = strlen(u);
    uint8_t tsBE[8]; SG_EncodeBE64(ts, tsBE);
    size_t sl = 0;
    uint8_t *sig = SG_SignPSS(rsa, _pendingNonce, SGP_NONCE_LEN, (const uint8_t *)u, ul, tsBE, 8, &sl);
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


NSString *SGP_BeginFirstTimeRegistration(void) {
    if (!SGP_IsConnected()) return nil;

    uint8_t bytes[16];
    SecRandomCopyBytes(kSecRandomDefault, sizeof(bytes), bytes);
    bytes[6] = (bytes[6] & 0x0F) | 0x40; bytes[8] = (bytes[8] & 0x3F) | 0x80;
    NSString *address = [NSString stringWithFormat:@"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]];

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
        return nil;
    }
    BIO_read(privBio, privBuf, (int)privLen);
    BIO_free(privBio);
    _regPendingPrivKey    = privBuf;
    _regPendingPrivKeyLen = (size_t)privLen;

    uint8_t *pubDer = NULL;
    int pubDerLen = i2d_RSA_PUBKEY(rsa, &pubDer);

    _regTimestamp = SG_GetCorrectedTime();
    uint8_t tsBE[8]; SG_EncodeBE64(_regTimestamp, tsBE);

    NSMutableData *payload = [NSMutableData data];
    uint16_t addrLen = (uint16_t)[address length];
    uint8_t addrLenBE[2] = {(uint8_t)(addrLen >> 8), (uint8_t)(addrLen & 0xFF)};
    [payload appendBytes:addrLenBE length:2];
    [payload appendBytes:[address UTF8String] length:addrLen];
    uint8_t keyLenBE[2] = {(uint8_t)(pubDerLen >> 8), (uint8_t)(pubDerLen & 0xFF)};
    [payload appendBytes:keyLenBE length:2];
    [payload appendBytes:pubDer length:pubDerLen];
    [payload appendBytes:tsBE length:8];
    uint32_t ver = htonl(SGP_VERSION); [payload appendBytes:&ver length:4];

    _regPendingAddress = [address retain];
    _regPendingRSA = rsa; 
    OPENSSL_free(pubDer);

    SGP_LowLevelSend(SGP_C_REGISTER, [payload bytes], (uint32_t)[payload length]);
    return address;
}

void SGP_ZeroAndFreeKeyMaterial(char *pemBuf, size_t len) {
    if (!pemBuf) return;
    volatile char *vp = pemBuf;
    for (size_t i = 0; i < len; i++) vp[i] = 0;
    free(pemBuf);
}

void SGP_SetDelegate(id<SGProtocolDelegate> delegate) { _delegate = delegate; }
BOOL SGP_IsConnected(void) { return (_ssl != NULL && _sock >= 0); }
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
    uint8_t seq[8];
    SG_EncodeBE64((int64_t)_pingSeq, seq);
    pthread_mutex_unlock(&_pingLock);

    if (SGP_LowLevelSend(SGP_C_PING, seq, 8) != 0) {
        pthread_mutex_lock(&_pingLock);
        _pingPendingSince = 0.0;
        pthread_mutex_unlock(&_pingLock);
        return NO;
    }
    return YES;
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
    if (_regPendingRSA) { RSA_free(_regPendingRSA); _regPendingRSA = NULL; }
    [_regPendingAddress release]; _regPendingAddress = nil;
    if (_regPendingPrivKey) {
        SGP_ZeroAndFreeKeyMaterial(_regPendingPrivKey, _regPendingPrivKeyLen);
        _regPendingPrivKey    = NULL;
        _regPendingPrivKeyLen = 0;
    }
    _pingPendingSince = 0.0;
    _lastFrameReceivedAt = 0.0;
}

int SGP_ConnectToServer(const char *ip, int port, NSString *pinnedCert) {
    signal(SIGPIPE, SIG_IGN);
    SGP_DisconnectFromServer();
    _lastRetryHint = 0;
    _lastFrameReceivedAt = 0.0;

    _sslctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_options(_sslctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    SSL_CTX_set_verify(_sslctx, SSL_VERIFY_PEER, NULL);
    const char *utf8Cert = [pinnedCert UTF8String];
    BIO *b = BIO_new_mem_buf((void *)utf8Cert, (int)strlen(utf8Cert));
    X509 *x = PEM_read_bio_X509(b, NULL, 0, NULL);
    if (!x) {
        SGLOGE(SGP, "ConnectToServer: OpenSSL failed to read PEM X509 certificate!");
        unsigned long openSslErr;
        while ((openSslErr = ERR_get_error()) != 0) {
            char errBuf[256];
            ERR_error_string_n(openSslErr, errBuf, sizeof(errBuf));
            SGLOGE(SGP, "ConnectToServer: OpenSSL error: %s", errBuf);
        }
    } else {
        X509_STORE_add_cert(SSL_CTX_get_cert_store(_sslctx), x);
        X509_free(x);
    }
    BIO_free(b);

    _sock = socket(AF_INET, SOCK_STREAM, 0);
    if (_sock < 0) { SGP_DisconnectFromServer(); return -1; }

    int yes = 1;
    setsockopt(_sock, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

    int flags = fcntl(_sock, F_GETFL, 0);
    fcntl(_sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    int connectResult = connect(_sock, (struct sockaddr *)&addr, sizeof(addr));
    if (connectResult < 0 && errno != EINPROGRESS) {
        SGP_DisconnectFromServer();
        return -2;
    }

    if (connectResult < 0) {
        if (_sock >= FD_SETSIZE) { SGP_DisconnectFromServer(); return -3; }
        fd_set wfds; FD_ZERO(&wfds); FD_SET(_sock, &wfds);
        struct timeval tv = {10, 0};
        int sel = select(_sock + 1, NULL, &wfds, NULL, &tv);
        if (sel <= 0) { SGP_DisconnectFromServer(); return -3; }

        int sockErr = 0; socklen_t errLen = sizeof(sockErr);
        getsockopt(_sock, SOL_SOCKET, SO_ERROR, &sockErr, &errLen);
        if (sockErr != 0) { SGP_DisconnectFromServer(); return -4; }
    }

    fcntl(_sock, F_SETFL, flags);

    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    _ssl = SSL_new(_sslctx);
    SSL_set_fd(_ssl, _sock);
    if (SSL_connect(_ssl) != 1) { SGP_DisconnectFromServer(); return -7; }

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

void SGP_SendClientDisconnect(void) {
    if (!SGP_IsConnected()) return;
    uint8_t reason = SGP_DISC_NORMAL;
    SGP_LowLevelSend(SGP_C_DISCONNECT, &reason, 1);
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
            if (pingIntervalSec <= 0.0) return SGP_OK;

            pthread_mutex_lock(&_pingLock);
            if (_pingPendingSince > 0.0) {
                pthread_mutex_unlock(&_pingLock);
                return SGP_ERR_TIMEOUT;
            }
            _pingSeq++;
            _pingPendingSince = SG_GetMonotonicSeconds();
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

    if (hdr[0] != SGP_MAGIC || hdr[1] != SGP_VERSION) {
        SGLOGW(SGP, "Invalid magic/version: 0x%02X 0x%02X (expected 0x%02X 0x%02X)",
               hdr[0], hdr[1], SGP_MAGIC, SGP_VERSION);
        return SGP_ERR_PROTO;
    }

    if (hdr[3] != 0x00) {
        SGLOGW(SGP, "Non-zero reserved header byte: 0x%02X", hdr[3]);
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
            [SGP_S_REGISTER_OK]   = {  4,   4 },
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
                SGLOGW(SGP, "Payload size %u out of range [%u, %u] for server type 0x%02X — rejecting frame",
                       len, kServerBounds[idx].min, kServerBounds[idx].max, idx);
                return SGP_ERR_PROTO;
            }
        }
    }

    uint8_t *raw = NULL;
    if (len > 0) {
        raw = malloc(len);
        if (!raw) return SGP_ERR_IO;
        if (SG_SSLReadExact(raw, (int)len) != 0) { free(raw); return SGP_ERR_IO; }
    }

    switch (type) {
        case SGP_S_NOTIFY:
        case SGP_S_AUTH_OK:
        case SGP_S_POLL_DONE:
        case SGP_S_PONG:
            pthread_mutex_lock(&_pingLock);
            _pingPendingSince = 0.0;
            pthread_mutex_unlock(&_pingLock);
            break;
        default:
            break;
    }

    int result = SGP_OK;

    switch (type) {
        case SGP_S_HELLO: {
            [_delegate protocolDidReceiveWelcomeChallenge];
            break;
        }
        case SGP_S_CHALLENGE: {
            if (len < SGP_NONCE_LEN) { result = SGP_ERR_PROTO; goto cleanup; }
            memcpy(_pendingNonce, raw, SGP_NONCE_LEN); _hasPendingNonce = YES;
            if (_regPendingAddress) SG_SendChallengeResponse(SGP_C_REGISTER_RESP, _regPendingRSA, _regPendingAddress, _regTimestamp);
            else SG_SendChallengeResponse(SGP_C_LOGIN_RESP, _userPrivKey, _userAddress, _loginTimestamp);
            break;
        }
        case SGP_S_AUTH_OK: {
            [_delegate protocolDidAuthenticateSuccessfully];
            break;
        }
        case SGP_S_NOTIFY: {
            if (len < SGP_NOTIFY_MIN_PAYLOAD) { result = SGP_ERR_PROTO; goto cleanup; }

            NSData *rk  = [NSData dataWithBytes:raw length:SGP_ROUTING_KEY_LEN];
            NSData *mid = [NSData dataWithBytes:raw + SGP_ROUTING_KEY_LEN length:SGP_MSG_ID_LEN];
            int64_t deviceSeq = SG_DecodeBE64(raw + SGP_NOTIFY_OFF_SEQ);
            int64_t expiresAt = SG_DecodeBE64(raw + SGP_NOTIFY_OFF_EXPIRES_AT);
            uint32_t dl = SG_DecodeBE32(raw + SGP_NOTIFY_OFF_DATA_LEN);

            if ((uint64_t)SGP_NOTIFY_MIN_PAYLOAD + dl > (uint64_t)len) {
                SGLOGW(SGP, "Protocol bounds violation in S_NOTIFY (dl=%u, len=%u)", dl, len);
                result = SGP_ERR_PROTO; goto cleanup;
            }

            NSMutableDictionary *notif = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                rk,  @"routing_key",
                mid, @"msg_id",
                @(raw[SGP_NOTIFY_OFF_FLAGS] & 0x01), @"is_encrypted",
                @(deviceSeq), @"device_seq",
                nil];
            notif[@"data"] = [NSData dataWithBytes:raw + SGP_NOTIFY_MIN_PAYLOAD length:dl];
            if (expiresAt > 0) notif[@"expires_at"] = @(expiresAt);

            if (raw[SGP_NOTIFY_OFF_FLAGS] & 0x01) {
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
            if (reason == SGP_DISC_AUTH_FAIL) { result = SGP_ERR_AUTH;     goto cleanup; }
            if (reason == SGP_DISC_REPLACED)  { result = SGP_ERR_REPLACED; goto cleanup; }
            result = SGP_ERR_CLOSED; goto cleanup;
        }
        case SGP_S_REGISTER_OK: {
            uint32_t serverVer = SG_DecodeBE32(raw);
            NSString *capturedAddress  = [_regPendingAddress autorelease];
            char     *capturedPemKey   = _regPendingPrivKey;
            size_t    capturedPemLen   = _regPendingPrivKeyLen;
            RSA      *capturedRSA      = _regPendingRSA;
            _regPendingAddress    = nil;
            _regPendingPrivKey    = NULL;
            _regPendingPrivKeyLen = 0;
            _regPendingRSA        = NULL;
            RSA_free(capturedRSA);
            [_delegate protocolDidCompleteRegistrationWithAddress:capturedAddress
                                                       privateKey:capturedPemKey
                                                    serverVersion:serverVer];
            (void)capturedPemLen;
            break;
        }
        case SGP_S_REGISTER_FAIL: {
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
            SGLOGE(SGP, "Registration failed: code=%u reason=%s", code, [reason UTF8String]);
            if (_regPendingRSA) { RSA_free(_regPendingRSA); _regPendingRSA = NULL; }
            [_regPendingAddress release]; _regPendingAddress = nil;
            if (_regPendingPrivKey) {
                SGP_ZeroAndFreeKeyMaterial(_regPendingPrivKey, _regPendingPrivKeyLen);
                _regPendingPrivKey    = NULL;
                _regPendingPrivKeyLen = 0;
            }
            [_delegate protocolDidFailRegistrationWithCode:code reason:reason];
            break;
        }
        case SGP_S_PONG: {
            pthread_mutex_lock(&_pingLock);
            uint64_t seq = _pingSeq;
            pthread_mutex_unlock(&_pingLock);
            if (SG_DecodeBE64(raw) == (int64_t)seq) {
                pthread_mutex_lock(&_pingLock);
                _pingPendingSince = 0.0;
                pthread_mutex_unlock(&_pingLock);
                [_delegate protocolDidReceiveKeepAlivePong];
            }
            break;
        }
        case SGP_S_PING: {
            SGP_LowLevelSend(SGP_C_PONG, raw, len);
            break;
        }
        case SGP_S_POLL_DONE: {
            [_delegate protocolDidFinishOfflineQueueDrain];
            break;
        }
        case SGP_S_TIME_SYNC: {
            int64_t serverTime = SG_DecodeBE64(raw);
            int64_t localTime  = (int64_t)time(NULL);
            int64_t offset     = serverTime - localTime;
            pthread_mutex_lock(&_sendLock);
            _clockSkewSeconds = offset;
            pthread_mutex_unlock(&_sendLock);
            SGLOGI(SGP, "Time sync: server=%lld local=%lld offset=%llds (skew applied)", serverTime, localTime, offset);
            [_delegate protocolDidReceiveTimeSyncWithOffset:offset];
            break;
        }
        default: break;
    }

cleanup:
    free(raw);
    return result;
}

void SGP_RequestOfflineMessages(void) {
    if (!SGP_IsConnected()) return;
    int64_t lastSeq = [[SGDatabaseManager sharedManager] lastDeliveredSeq];
    uint8_t seqBE[8];
    SG_EncodeBE64(lastSeq, seqBE);
    SGP_LowLevelSend(SGP_C_POLL, seqBE, 8);
}
