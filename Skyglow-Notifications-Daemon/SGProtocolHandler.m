#import "SGProtocolHandler.h"
#import "SGDatabaseManager.h"
#import "SGConfiguration.h"
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

static NSString *_userAddress = nil;
static RSA      *_userPrivKey = NULL;
static int64_t   _loginTimestamp = 0;
static uint8_t   _pendingNonce[SGP_NONCE_LEN];
static BOOL      _hasPendingNonce = NO;

// --- Used for Heartbeat / Ping Logic ---
static uint64_t  _pingSeq = 0;
static double    _pingPendingSince = 0.0;
static uint32_t  _lastRetryHint = 0;

// --- Used for Device Registration Flow ---
static NSString *_regPendingAddress = nil;
static NSString *_regPendingPrivKey = nil;
static RSA      *_regPendingRSA = NULL;
static int64_t   _regTimestamp = 0;

// --- Used for Synchronous Token Registration ---
static NSMutableDictionary *_tokenWaiters = nil;
static dispatch_once_t      _tokenOnce;

// ── Private Helpers ────────────────────────────────────────────────

static double SG_GetMonotonicSeconds(void) {
    static mach_timebase_info_data_t tb;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ mach_timebase_info(&tb); });
    return (double)mach_absolute_time() * (double)tb.numer / ((double)tb.denom * 1.0e9);
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

/// Waits for the underlying socket to become ready for the given SSL direction.
/// Returns 0 on ready, -1 on error/timeout.
static int SG_WaitForSocket(int sock, int forWrite, int timeoutSec) {
    if (sock < 0) return -1;
    fd_set fds; FD_ZERO(&fds); FD_SET(sock, &fds);
    struct timeval tv = {timeoutSec, 0};
    if (forWrite)
        return (select(sock + 1, NULL, &fds, NULL, &tv) > 0) ? 0 : -1;
    else
        return (select(sock + 1, &fds, NULL, NULL, &tv) > 0) ? 0 : -1;
}

static int SG_SSLReadExact(void *buf, int len) {
    if (!_ssl) return -1;
    int total = 0;
    while (total < len) {
        int n = SSL_read(_ssl, (char *)buf + total, len - total);
        if (n > 0) { total += n; continue; }
        int err = SSL_get_error(_ssl, n);
        if (err == SSL_ERROR_WANT_READ) {
            if (SG_WaitForSocket(_sock, 0, 10) != 0) return -1;
            continue;
        }
        if (err == SSL_ERROR_WANT_WRITE) {
            if (SG_WaitForSocket(_sock, 1, 10) != 0) return -1;
            continue;
        }
        return -1;
    }
    return 0;
}

static int SG_SSLWriteLocked(const void *buf, int len) {
    if (!_ssl) return -1;
    int total = 0;
    while (total < len) {
        int n = SSL_write(_ssl, (const char *)buf + total, len - total);
        if (n > 0) { total += n; continue; }
        int err = SSL_get_error(_ssl, n);
        if (err == SSL_ERROR_WANT_WRITE) {
            if (SG_WaitForSocket(_sock, 1, 10) != 0) return -1;
            continue;
        }
        if (err == SSL_ERROR_WANT_READ) {
            if (SG_WaitForSocket(_sock, 0, 10) != 0) return -1;
            continue;
        }
        return -1;
    }
    return 0;
}

static int SGP_LowLevelSend(SGPMsgType type, const void *payload, uint32_t len) {
    if (len > SGP_MAX_PAYLOAD_LEN) return -1;

    // Atomic single-write: protocol spec §3 requires header + payload
    // in one write call. Heap-allocated to avoid 4KB stack pressure.
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
    memset(em, 0, size); // Zero padding buffer
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

    // Buffer overflow & privilege escalation protection
    if (sl > 512) {
        memset(sig, 0, sl);
        free(sig);
        return -1;
    }

    uint8_t p[8 + 2 + 512];
    memcpy(p, tsBE, 8);
    p[8] = (sl >> 8) & 0xFF; p[9] = sl & 0xFF;
    memcpy(p + 10, sig, sl);
    memset(sig, 0, sl); // Zero signature material
    free(sig);
    return SGP_LowLevelSend(type, p, (uint32_t)(10 + sl));
}

// ── Registration Logic ─────────────────────────────────────────────

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
    char *privBuf = malloc(privLen + 1);
    BIO_read(privBio, privBuf, (int)privLen);
    privBuf[privLen] = '\0';
    _regPendingPrivKey = [[NSString stringWithUTF8String:privBuf] retain];
    memset(privBuf, 0, privLen); // Zero private key material
    free(privBuf); BIO_free(privBio);

    uint8_t *pubDer = NULL;
    int pubDerLen = i2d_RSA_PUBKEY(rsa, &pubDer);

    _regTimestamp = (int64_t)time(NULL);
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

// ── Public API Implementation ───────────────────────────────────────

void SGP_SetDelegate(id<SGProtocolDelegate> delegate) { _delegate = delegate; }
BOOL SGP_IsConnected(void) { return (_ssl != NULL && _sock >= 0); }
uint32_t SGP_GetLastDisconnectRetryAfter(void) { return _lastRetryHint; }

void SGP_AbortConnection(void) {
    // Safely unblocks select() / SSL_read() without mutating the _ssl pointers dynamically 
    // to prevent EXC_BAD_ACCESS Use-After-Free crashes. Primary thread will free on EOF.
    if (_sock >= 0) {
        shutdown(_sock, SHUT_RDWR);
        close(_sock);
        _sock = -1;
    }
}

void SGP_DisconnectFromServer(void) {
    if (_userPrivKey) { RSA_free(_userPrivKey); _userPrivKey = NULL; }
    if (_ssl) { SSL_shutdown(_ssl); SSL_free(_ssl); _ssl = NULL; }
    if (_sslctx) { SSL_CTX_free(_sslctx); _sslctx = NULL; }
    if (_sock >= 0) { close(_sock); _sock = -1; }
    [_userAddress release]; _userAddress = nil;
    if (_regPendingRSA) { RSA_free(_regPendingRSA); _regPendingRSA = NULL; }
    [_regPendingAddress release]; _regPendingAddress = nil;
    [_regPendingPrivKey release]; _regPendingPrivKey = nil;
    _pingPendingSince = 0.0;
}

int SGP_ConnectToServer(const char *ip, int port, NSString *pinnedCert) {
    signal(SIGPIPE, SIG_IGN);
    SGP_DisconnectFromServer();
    _lastRetryHint = 0;

    _sslctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_options(_sslctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    SSL_CTX_set_verify(_sslctx, SSL_VERIFY_PEER, NULL);

    const char *utf8Cert = [pinnedCert UTF8String];
    BIO *b = BIO_new_mem_buf((void *)utf8Cert, (int)strlen(utf8Cert));
    X509 *x = PEM_read_bio_X509(b, NULL, 0, NULL);
    if (!x) {
        NSLog(@"[SGP_ConnectToServer] OpenSSL Failed to read PEM X509 Certificate!");
        unsigned long openSslErr;
        while ((openSslErr = ERR_get_error()) != 0) {
            char errBuf[256];
            ERR_error_string_n(openSslErr, errBuf, sizeof(errBuf));
            NSLog(@"[SGP_ConnectToServer] OpenSSL Error: %s", errBuf);
        }
    } else {
        X509_STORE_add_cert(SSL_CTX_get_cert_store(_sslctx), x);
        X509_free(x);
    }
    BIO_free(b);

    _sock = socket(AF_INET, SOCK_STREAM, 0);
    if (_sock < 0) { SGP_DisconnectFromServer(); return -1; }

    // TCP_NODELAY: disable Nagle's algorithm for low-latency notification delivery
    int yes = 1;
    setsockopt(_sock, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

    // Non-blocking connect with explicit 10-second timeout
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
        // Wait for connect to complete with timeout
        fd_set wfds; FD_ZERO(&wfds); FD_SET(_sock, &wfds);
        struct timeval tv = {10, 0};
        int sel = select(_sock + 1, NULL, &wfds, NULL, &tv);
        if (sel <= 0) { SGP_DisconnectFromServer(); return -3; }

        int sockErr = 0; socklen_t errLen = sizeof(sockErr);
        getsockopt(_sock, SOL_SOCKET, SO_ERROR, &sockErr, &errLen);
        if (sockErr != 0) { SGP_DisconnectFromServer(); return -4; }
    }

    // Restore blocking mode for SSL
    fcntl(_sock, F_SETFL, flags);

    // Set read/write timeouts for post-connect I/O
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
    _loginTimestamp = (int64_t)time(NULL);

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

    // Try to send it instantly over the live socket
    if (SGP_IsConnected() && SGP_LowLevelSend(SGP_C_ACK, p, 17) == 0) return;

    // The network is down or the send failed.
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
    NSArray *keys = [[SGDatabaseManager sharedManager] allActiveRoutingKeys];
    NSUInteger total = [keys count];
    NSUInteger maxPerChunk = (SGP_MAX_PAYLOAD_LEN - 3) / 32;
    NSUInteger offset = 0;

    do {
        NSUInteger count = MIN(total - offset, maxPerChunk);
        BOOL hasMore = (offset + count < total);
        NSMutableData *p = [NSMutableData data];
        uint8_t flags = hasMore ? 1 : 0; [p appendBytes:&flags length:1];
        uint8_t cBE[2] = {(uint8_t)(count >> 8), (uint8_t)(count & 0xFF)}; [p appendBytes:cBE length:2];
        for (NSUInteger i = 0; i < count; i++) [p appendData:keys[offset + i]];
        
        if (SGP_LowLevelSend(SGP_C_FILTER, [p bytes], (uint32_t)[p length]) != 0) break;
        offset += count;
    } while (offset < total);
}

BOOL SGP_RegisterDeviceToken(NSData *routingKey, NSString *bundleID) {
    if (!SGP_IsConnected()) return NO;

    dispatch_once(&_tokenOnce, ^{ _tokenWaiters = [[NSMutableDictionary alloc] init]; });
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    
    @synchronized(_tokenWaiters) { _tokenWaiters[bundleID] = [NSValue valueWithPointer:sema]; }

    const char *bid = [bundleID UTF8String]; uint16_t bl = (uint16_t)strlen(bid);
    NSMutableData *p = [NSMutableData data]; [p appendData:routingKey];
    uint8_t blBE[2] = {(uint8_t)(bl >> 8), (uint8_t)(bl & 0xFF)};
    [p appendBytes:blBE length:2]; [p appendBytes:bid length:bl];

    if (SGP_LowLevelSend(SGP_C_REG_TOKEN, [p bytes], (uint32_t)[p length]) != 0) {
        @synchronized(_tokenWaiters) { [_tokenWaiters removeObjectForKey:bundleID]; }
        dispatch_release(sema);
        return NO;
    }
    
    long rc = dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
    @synchronized(_tokenWaiters) { [_tokenWaiters removeObjectForKey:bundleID]; }
    
    dispatch_release(sema);
    return (rc == 0);
}

void SGP_SendClientDisconnect(void) {
    if (!SGP_IsConnected()) return;
    uint8_t reason = SGP_DISC_NORMAL;
    SGP_LowLevelSend(SGP_C_DISCONNECT, &reason, 1);
}

int SGP_ProcessNextIncomingMessage(double pingIntervalSec) {
    if (!SGP_IsConnected()) return SGP_ERR_IO;

    // CRITICAL: Check SSL_pending() BEFORE select().
    // After SSL_connect(), OpenSSL may have buffered the S_HELLO
    // data internally (read-ahead). select() checks the raw socket
    // FD which appears empty, causing an infinite block.
    int hasPending = (_ssl && SSL_pending(_ssl) > 0);

    if (!hasPending) {
        fd_set rfds; FD_ZERO(&rfds); FD_SET(_sock, &rfds);
    
        struct timeval tv = {(long)pingIntervalSec, 0};
        struct timeval *tv_ptr = (pingIntervalSec > 0.0) ? &tv : NULL;

        if (_pingPendingSince > 0.0) {
            double elapsed = SG_GetMonotonicSeconds() - _pingPendingSince;
            if (elapsed >= (double)SGP_PONG_TIMEOUT_SEC) return SGP_ERR_TIMEOUT;
            tv.tv_sec = (long)(SGP_PONG_TIMEOUT_SEC - elapsed);
            tv_ptr = &tv;
        }

        int sel = select(_sock + 1, &rfds, NULL, NULL, tv_ptr);
        if (sel < 0) return (errno == EINTR) ? SGP_OK : SGP_ERR_IO;
    
        if (sel == 0) {
            if (pingIntervalSec <= 0.0) return SGP_OK; 
        
            if (_pingPendingSince > 0.0) return SGP_ERR_TIMEOUT;
            _pingSeq++; _pingPendingSince = SG_GetMonotonicSeconds();
            uint8_t seq[8]; SG_EncodeBE64((int64_t)_pingSeq, seq);
            SGP_LowLevelSend(SGP_C_PING, seq, 8);
            return SGP_OK;
        }
    }

    uint8_t hdr[8];
    if (SG_SSLReadExact(hdr, 8) != 0) return SGP_ERR_IO;

    // Safe unaligned read for payload length
    uint32_t len = SG_DecodeBE32(hdr + 4);

    if (len > SGP_MAX_PAYLOAD_LEN) return SGP_ERR_PROTO;

    uint8_t raw[SGP_MAX_PAYLOAD_LEN];
    if (len > 0) {
        if (SG_SSLReadExact(raw, (int)len) != 0) return SGP_ERR_IO;
    }
    
    SGPMsgType type = (SGPMsgType)hdr[2];

    // Reset ping timer only on valid server-originated data frames
    if (type != SGP_S_PONG) {
        _pingPendingSince = 0.0;
    }

    switch (type) {
        case SGP_S_HELLO: {
            [_delegate protocolDidReceiveWelcomeChallenge];
            break;
        }
        case SGP_S_CHALLENGE: {
            if (len < 32) return SGP_ERR_PROTO;
            memcpy(_pendingNonce, raw, 32); _hasPendingNonce = YES;
            if (_regPendingAddress) SG_SendChallengeResponse(SGP_C_REGISTER_RESP, _regPendingRSA, _regPendingAddress, _regTimestamp);
            else SG_SendChallengeResponse(SGP_C_LOGIN_RESP, _userPrivKey, _userAddress, _loginTimestamp);
            break;
        }
        case SGP_S_AUTH_OK: [_delegate protocolDidAuthenticateSuccessfully]; break;
        case SGP_S_NOTIFY: {
            if (len < 70) return SGP_ERR_PROTO; 
            
            NSData *rk = [NSData dataWithBytes:raw length:32];
            NSData *mid = [NSData dataWithBytes:raw + 32 length:16];
            uint32_t dl = SG_DecodeBE32(raw + 66);
            
            // Buffer overflow & integer wraparound protection
            if ((uint64_t)70 + dl > len) {
                NSLog(@"[SGP] Protocol bounds violation in S_NOTIFY");
                return SGP_ERR_PROTO;
            }
            
            NSMutableDictionary *notif = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                rk, @"routing_key", mid, @"msg_id", @(raw[64] & 0x01), @"is_encrypted", nil];
            notif[@"data"] = [NSData dataWithBytes:raw + 70 length:dl];
            
            if (raw[64] & 0x01) {
                if ((uint64_t)70 + dl + 12 > len) return SGP_ERR_PROTO;
                notif[@"iv"] = [NSData dataWithBytes:raw + 70 + dl length:12];
            }
            [_delegate protocolDidReceiveNotification:notif];
            break;
        }
        case SGP_S_DISCONNECT: {
            if (len < 1) return SGP_ERR_PROTO;
            uint8_t reason = raw[0];
            _lastRetryHint = (len >= 5) ? SG_DecodeBE32(raw + 1) : 0;
            if (reason == SGP_DISC_AUTH_FAIL) return SGP_ERR_AUTH;
            if (reason == SGP_DISC_REPLACED) return SGP_ERR_REPLACED;
            return SGP_ERR_CLOSED;
        }
        case SGP_S_TOKEN_ACK: {
            if (len < 34) return SGP_ERR_PROTO;
            uint16_t bl = ((uint16_t)raw[32] << 8) | (uint16_t)raw[33];
            if ((uint64_t)34 + bl > len) return SGP_ERR_PROTO;
            
            NSString *bid = [[[NSString alloc] initWithBytes:raw + 34 length:bl encoding:NSUTF8StringEncoding] autorelease];
            @synchronized(_tokenWaiters) { 
                NSValue *val = _tokenWaiters[bid];
                if (val) {
                    dispatch_semaphore_t sema = (dispatch_semaphore_t)[val pointerValue];
                    dispatch_semaphore_signal(sema);
                }
            }
            [_delegate protocolDidCompleteTokenRegistration:bid];
            break;
        }
        case SGP_S_REGISTER_OK: {
            if (len < 4) return SGP_ERR_PROTO;
            uint32_t serverVer = SG_DecodeBE32(raw);
            [_delegate protocolDidCompleteRegistrationWithAddress:[_regPendingAddress autorelease] privateKey:[_regPendingPrivKey autorelease] serverVersion:serverVer];
            RSA_free(_regPendingRSA); _regPendingRSA = NULL; _regPendingAddress = nil; _regPendingPrivKey = nil;
            break;
        }
        case SGP_S_REGISTER_FAIL: {
            uint8_t code = (len >= 1) ? raw[0] : 0xFF;
            NSString *reason = nil;
            if (len >= 4) {
                uint16_t rl = ((uint16_t)raw[1] << 8) | (uint16_t)raw[2];
                if ((uint64_t)3 + rl <= len) {
                    reason = [[[NSString alloc] initWithBytes:raw + 3 length:rl encoding:NSUTF8StringEncoding] autorelease];
                }
            }
            if (!reason) reason = @"Unknown";
            NSLog(@"[SGP] Registration failed: code=%u reason=%@", code, reason);
            if (_regPendingRSA) { RSA_free(_regPendingRSA); _regPendingRSA = NULL; }
            [_regPendingAddress release]; _regPendingAddress = nil;
            [_regPendingPrivKey release]; _regPendingPrivKey = nil;
            [_delegate protocolDidFailRegistrationWithCode:code reason:reason];
            break;
        }
        case SGP_S_PONG: {
            if (len < 8) return SGP_ERR_PROTO;
            if (SG_DecodeBE64(raw) == (int64_t)_pingSeq) {
                _pingPendingSince = 0.0;
                [_delegate protocolDidReceiveKeepAlivePong];
            }
            break;
        }
        case SGP_S_PING: {
            // Server-initiated keepalive: echo the payload back as C_PONG
            SGP_LowLevelSend(SGP_C_PONG, raw, len);
            break;
        }
        case SGP_S_POLL_DONE: {
            [_delegate protocolDidFinishOfflineQueueDrain];
            break;
        }
        case SGP_S_TIME_SYNC: {
            if (len >= 8) {
                int64_t serverTime = SG_DecodeBE64(raw);
                int64_t localTime = (int64_t)time(NULL);
                int64_t offset = serverTime - localTime;
                NSLog(@"[SGP] Time sync: server=%lld local=%lld offset=%llds", serverTime, localTime, offset);
                [_delegate protocolDidReceiveTimeSyncWithOffset:offset];
            }
            break;
        }
        default: break;
    }
    return SGP_OK;
}

void SGP_RequestOfflineMessages(void) {
    if (!SGP_IsConnected()) return;
    SGP_LowLevelSend(SGP_C_POLL, NULL, 0);
}