/*
 * Protocol.m — Skyglow Notification Daemon
 * Skyglow Protocol version 2 (SGP/2) implementation.
 *
 * See Protocol.h for the full wire format, authentication flow, and
 * message catalogue. This file contains only implementation details.
 *
 * ── Threading model ────────────────────────────────────────────────
 *
 *   connectToServer / disconnectFromServer / startLogin
 *     Called exclusively from the connection loop thread.
 *
 *   handleMessage
 *     Called exclusively from the connection loop thread. Uses select()
 *     with SGP_PING_INTERVAL_SEC timeout to drive Ping/Pong without
 *     a separate keepalive thread.
 *
 *   ackNotification / sendFeedback / sendClientDisconnect
 *     Called from the connection loop thread (notification dispatch or
 *     shutdown path). Serialised by _sendLock.
 *
 *   registerDeviceToken
 *     Called from the MachMsgs thread. Serialised by _sendLock for
 *     the write; blocks on a semaphore for up to 5s for the server ack.
 *
 * All writes go through sendMsg(), which builds a single contiguous
 * buffer (header + payload) and writes it under _sendLock. Reads are
 * single-threaded — only the connection loop calls sslReadExact. The
 * lock therefore serialises concurrent writers without touching reads.
 */

#import "Protocol.h"
#include <Foundation/Foundation.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <time.h>
#include <mach/mach_time.h>   // mach_absolute_time — available all iOS versions

/* ─────────────────────────────────────────────────────────────────
 * Connection timeouts
 * ───────────────────────────────────────────────────────────────── */

/// TCP connect() hard deadline.
#define CONNECT_TIMEOUT_SEC     10

/// SO_SNDTIMEO / SO_RCVTIMEO applied only during SSL_connect.
/// Cleared after a successful handshake.
#define TLS_HANDSHAKE_TIMEOUT   15

/// TCP_KEEPALIVE idle threshold before the kernel starts probing.
/// Matches APNS best-practice for persistent connections.
#define TCP_KEEPALIVE_IDLE_SEC  60

/* ─────────────────────────────────────────────────────────────────
 * File-private connection state
 * ───────────────────────────────────────────────────────────────── */

static id<NotificationDelegate>  _delegate   = nil;

static SSL     *_ssl    = NULL;
static SSL_CTX *_sslctx = NULL;
static int      _sock   = -1;

/// Serialises all SSL_write calls. Multiple threads may send
/// (MachMsgs → registerDeviceToken; connection loop → Ping/Ack/Disconnect).
/// Only one reader exists (the connection loop), so reads need no lock.
static pthread_mutex_t  _sendLock = PTHREAD_MUTEX_INITIALIZER;

/// Device address from the profile, set by startLogin().
static NSString *_userAddress    = nil;

/// Client RSA private key. Ownership belongs to Protocol.m.
/// Set by startLogin(); freed in disconnectFromServer() and in
/// startLogin() before reassignment to prevent leaks on mis-use.
static RSA      *_userPrivKey    = NULL;

/// Login timestamp sent in SGP_C_LOGIN, echoed verbatim in SGP_C_LOGIN_RESP.
static int64_t   _loginTimestamp = 0;

/// 32-byte nonce received in SGP_S_CHALLENGE. Consumed by sendLoginResponse.
static uint8_t   _pendingNonce[SGP_NONCE_LEN];
static BOOL      _hasPendingNonce = NO;

/// Monotonically increasing Ping sequence counter.
static uint64_t  _pingSeq = 0;

/// CLOCK_MONOTONIC time (seconds) when the outstanding Ping was sent.
/// 0 means no Ping is currently outstanding.
static double    _pingPendingSince = 0.0;

/// Token-registration semaphore table.
/// Key: bundleId (NSString) → Value: dispatch_semaphore_t
/// Protected by @synchronized(_tokenWaiters).
static NSMutableDictionary *_tokenWaiters    = nil;
static dispatch_once_t      _tokenWaitersOnce;

/* ─────────────────────────────────────────────────────────────────
 * Internal helpers
 * ───────────────────────────────────────────────────────────────── */

static void logSSLErrors(NSString *ctx) {
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        NSLog(@"[Protocol] %@: %s", ctx, buf);
    }
}

/// Monotonic clock in seconds. Uses mach_absolute_time() which is available
/// on all iOS versions (clock_gettime(CLOCK_MONOTONIC) requires iOS 10+).
/// Immune to NTP / wall-clock adjustments — safe for measuring Ping RTT.
static double monotonicSec(void) {
    // mach_timebase_info gives the conversion factor from mach ticks to nanoseconds.
    // We compute it once and cache it; the result is constant per boot.
    static mach_timebase_info_data_t tb;
    static dispatch_once_t           onceToken;
    dispatch_once(&onceToken, ^{ mach_timebase_info(&tb); });

    uint64_t ticks = mach_absolute_time();
    // ticks * (numer/denom) = nanoseconds
    return (double)ticks * (double)tb.numer / ((double)tb.denom * 1.0e9);
}

/* ─────────────────────────────────────────────────────────────────
 * Big-endian encode helpers
 * ───────────────────────────────────────────────────────────────── */

static void encodeBEInt64(int64_t v, uint8_t out[8]) {
    uint64_t u = (uint64_t)v;
    out[0]=(u>>56)&0xFF; out[1]=(u>>48)&0xFF;
    out[2]=(u>>40)&0xFF; out[3]=(u>>32)&0xFF;
    out[4]=(u>>24)&0xFF; out[5]=(u>>16)&0xFF;
    out[6]=(u>> 8)&0xFF; out[7]=(u    )&0xFF;
}

static void encodeBEUInt16(uint16_t v, uint8_t out[2]) {
    out[0]=(v>>8)&0xFF; out[1]=(v)&0xFF;
}

/* ─────────────────────────────────────────────────────────────────
 * SSL I/O — reads (single-threaded; no lock needed)
 * ───────────────────────────────────────────────────────────────── */

/// Read exactly len bytes into buf. Uses select() when SSL returns
/// WANT_READ / WANT_WRITE so we block the thread without spinning.
/// Returns 0 on success, -1 on any error or clean peer shutdown.
static int sslReadExact(void *buf, int len) {
    if (!_ssl || _sock < 0) return -1;

    int total = 0;
    while (total < len) {
        int n = SSL_read(_ssl, (char *)buf + total, len - total);
        if (n > 0) { total += n; continue; }

        int sslErr = SSL_get_error(_ssl, n);

        if (sslErr == SSL_ERROR_WANT_READ) {
            fd_set rfds; FD_ZERO(&rfds); FD_SET(_sock, &rfds);
            if (select(_sock+1, &rfds, NULL, NULL, NULL) < 0 && errno != EINTR) return -1;
            continue;
        }
        if (sslErr == SSL_ERROR_WANT_WRITE) {
            fd_set wfds; FD_ZERO(&wfds); FD_SET(_sock, &wfds);
            if (select(_sock+1, NULL, &wfds, NULL, NULL) < 0 && errno != EINTR) return -1;
            continue;
        }
        if (sslErr == SSL_ERROR_ZERO_RETURN)
            NSLog(@"[Protocol] SSL_read: server closed cleanly");
        else {
            NSLog(@"[Protocol] SSL_read error: ssl=%d errno=%d (%s)",
                  sslErr, errno, strerror(errno));
            logSSLErrors(@"SSL_read");
        }
        return -1;
    }
    return 0;
}

/* ─────────────────────────────────────────────────────────────────
 * SSL I/O — writes (CALLER MUST HOLD _sendLock)
 * ───────────────────────────────────────────────────────────────── */

/// Write exactly len bytes from buf. _sendLock must be held by caller.
static int sslWriteExactLocked(const void *buf, int len) {
    if (!_ssl || _sock < 0) return -1;

    int total = 0;
    while (total < len) {
        int n = SSL_write(_ssl, (const char *)buf + total, len - total);
        if (n > 0) { total += n; continue; }

        int sslErr = SSL_get_error(_ssl, n);

        if (sslErr == SSL_ERROR_WANT_WRITE) {
            fd_set wfds; FD_ZERO(&wfds); FD_SET(_sock, &wfds);
            if (select(_sock+1, NULL, &wfds, NULL, NULL) < 0 && errno != EINTR) return -1;
            continue;
        }
        if (sslErr == SSL_ERROR_WANT_READ) {
            fd_set rfds; FD_ZERO(&rfds); FD_SET(_sock, &rfds);
            if (select(_sock+1, &rfds, NULL, NULL, NULL) < 0 && errno != EINTR) return -1;
            continue;
        }
        NSLog(@"[Protocol] SSL_write error: ssl=%d errno=%d (%s)",
              sslErr, errno, strerror(errno));
        logSSLErrors(@"SSL_write");
        return -1;
    }
    return 0;
}

/* ─────────────────────────────────────────────────────────────────
 * sendMsg — builds and sends one complete SGP/2 frame
 *
 * Assembles the 8-byte header and payload into a single heap buffer
 * then writes the whole thing under _sendLock in one SSL_write call.
 * This prevents two concurrent senders from interleaving bytes, and
 * prevents Nagle from splitting the header from the payload.
 * ───────────────────────────────────────────────────────────────── */

static int sendMsg(SGPMsgType type, const void *payload, uint32_t payloadLen) {
    if (payloadLen > SGP_MAX_PAYLOAD_LEN) {
        NSLog(@"[Protocol] sendMsg: payload %u exceeds max %u", payloadLen, SGP_MAX_PAYLOAD_LEN);
        return -1;
    }

    size_t   frameLen = SGP_HEADER_SIZE + payloadLen;
    uint8_t *frame    = malloc(frameLen);
    if (!frame) return -1;

    frame[0] = SGP_MAGIC;
    frame[1] = SGP_VERSION;
    frame[2] = (uint8_t)type;
    frame[3] = 0x00;  // flags — reserved

    uint32_t lenBE = htonl(payloadLen);
    memcpy(frame + 4, &lenBE, 4);

    if (payloadLen > 0 && payload)
        memcpy(frame + SGP_HEADER_SIZE, payload, payloadLen);

    pthread_mutex_lock(&_sendLock);
    int rc = sslWriteExactLocked(frame, (int)frameLen);
    pthread_mutex_unlock(&_sendLock);

    free(frame);
    return rc;
}

/* ─────────────────────────────────────────────────────────────────
 * Non-blocking TCP connect with wall-clock timeout
 * ───────────────────────────────────────────────────────────────── */

static int connectWithTimeout(int fd, struct sockaddr *addr,
                               socklen_t addrLen, int timeoutSec) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;

    int rc = connect(fd, addr, addrLen);
    if (rc == 0) { fcntl(fd, F_SETFL, flags); return 0; }

    if (errno != EINPROGRESS) {
        NSLog(@"[Protocol] connect() failed immediately: %s (errno=%d)",
              strerror(errno), errno);
        fcntl(fd, F_SETFL, flags);
        return -1;
    }

    fd_set wfds; FD_ZERO(&wfds); FD_SET(fd, &wfds);
    struct timeval tv = { timeoutSec, 0 };
    rc = select(fd + 1, NULL, &wfds, NULL, &tv);

    // Restore blocking mode before inspecting result.
    fcntl(fd, F_SETFL, flags);

    if (rc == 0) {
        NSLog(@"[Protocol] connect() timed out after %ds", timeoutSec);
        errno = ETIMEDOUT;
        return -1;
    }
    if (rc < 0) {
        NSLog(@"[Protocol] select() on connect: %s", strerror(errno));
        return -1;
    }

    int soErr = 0; socklen_t soErrLen = sizeof(soErr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soErr, &soErrLen) < 0) return -1;
    if (soErr != 0) {
        NSLog(@"[Protocol] connect() deferred error: %s (errno=%d)",
              strerror(soErr), soErr);
        errno = soErr;
        return -1;
    }
    return 0;
}

/* ─────────────────────────────────────────────────────────────────
 * sendLoginResponse  (called from handleMessage on SGP_S_CHALLENGE)
 *
 * Computes RSA-PSS-SHA256 over:
 *   nonce[32] || device_address_utf8 || login_timestamp_be[8]
 * and sends SGP_C_LOGIN_RESP: timestamp[8] + sig_len[2] + sig[N].
 *
 * Why PSS?  Signing is the correct primitive for proving key possession.
 * RSA-OAEP decryption (SGP/1) proved you could decrypt a server-chosen
 * ciphertext, but didn't prevent a malicious server from using the
 * decryption oracle for other purposes. PSS is a standard, audited
 * signature scheme with a tighter security proof.
 * ───────────────────────────────────────────────────────────────── */

static int sendLoginResponse(void) {
    if (!_hasPendingNonce || !_userAddress || !_userPrivKey) {
        NSLog(@"[Protocol] sendLoginResponse: missing state");
        return -1;
    }

    const char *addrUTF8 = [_userAddress UTF8String];
    size_t addrLen = strlen(addrUTF8);

    uint8_t tsBE[8];
    encodeBEInt64(_loginTimestamp, tsBE);

    // EVP_PKEY_set1_RSA takes a reference — _userPrivKey lifetime unaffected.
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) { logSSLErrors(@"EVP_PKEY_new"); return -1; }
    if (EVP_PKEY_set1_RSA(pkey, _userPrivKey) != 1) {
        logSSLErrors(@"EVP_PKEY_set1_RSA"); EVP_PKEY_free(pkey); return -1;
    }

    EVP_MD_CTX  *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { EVP_PKEY_free(pkey); return -1; }

    EVP_PKEY_CTX *pkctx = NULL;
    if (EVP_DigestSignInit(mdctx, &pkctx, EVP_sha256(), NULL, pkey) != 1) {
        logSSLErrors(@"EVP_DigestSignInit");
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); return -1;
    }
    // RSA-PSS with salt length = digest length (32 bytes for SHA-256).
    if (EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING) != 1 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, RSA_PSS_SALTLEN_DIGEST) != 1) {
        logSSLErrors(@"PSS params");
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); return -1;
    }

    if (EVP_DigestSignUpdate(mdctx, _pendingNonce, SGP_NONCE_LEN) != 1 ||
        EVP_DigestSignUpdate(mdctx, addrUTF8, addrLen)            != 1 ||
        EVP_DigestSignUpdate(mdctx, tsBE, 8)                      != 1) {
        logSSLErrors(@"DigestSignUpdate");
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); return -1;
    }

    // First call: get length.
    size_t sigLen = 0;
    if (EVP_DigestSignFinal(mdctx, NULL, &sigLen) != 1) {
        logSSLErrors(@"DigestSignFinal(len)");
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); return -1;
    }

    uint8_t *sig = malloc(sigLen);
    if (!sig) { EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); return -1; }

    // Second call: sign.
    if (EVP_DigestSignFinal(mdctx, sig, &sigLen) != 1) {
        logSSLErrors(@"DigestSignFinal");
        free(sig); EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); return -1;
    }
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    _hasPendingNonce = NO;   // consume the nonce regardless of send result

    if (sigLen > 0xFFFF) {
        NSLog(@"[Protocol] Signature too long (%zu bytes)", sigLen);
        free(sig); return -1;
    }

    // Payload: timestamp[8] + sig_len[2] + sig[N]
    size_t  payloadLen = 8 + 2 + sigLen;
    uint8_t *payload   = malloc(payloadLen);
    if (!payload) { free(sig); return -1; }

    memcpy(payload, tsBE, 8);
    uint8_t sigLenBE[2]; encodeBEUInt16((uint16_t)sigLen, sigLenBE);
    memcpy(payload + 8,  sigLenBE, 2);
    memcpy(payload + 10, sig, sigLen);
    free(sig);

    int rc = sendMsg(SGP_C_LOGIN_RESP, payload, (uint32_t)payloadLen);
    free(payload);
    return rc;
}

/* ─────────────────────────────────────────────────────────────────
 * Ping helper
 * ───────────────────────────────────────────────────────────────── */

static int sendPing(void) {
    _pingSeq++;
    uint8_t seq[SGP_PING_SEQ_LEN];
    uint64_t s = _pingSeq;
    seq[0]=(s>>56)&0xFF; seq[1]=(s>>48)&0xFF; seq[2]=(s>>40)&0xFF; seq[3]=(s>>32)&0xFF;
    seq[4]=(s>>24)&0xFF; seq[5]=(s>>16)&0xFF; seq[6]=(s>> 8)&0xFF; seq[7]=(s    )&0xFF;
    _pingPendingSince = monotonicSec();
    NSLog(@"[Protocol] → Ping seq=%llu", (unsigned long long)_pingSeq);
    return sendMsg(SGP_C_PING, seq, SGP_PING_SEQ_LEN);
}

/* ─────────────────────────────────────────────────────────────────
 * Public API
 * ───────────────────────────────────────────────────────────────── */

void setNotificationDelegate(id<NotificationDelegate> delegate) {
    _delegate = delegate;
}

BOOL isConnected(void) {
    return (_ssl != NULL && _sock >= 0);
}

void disconnectFromServer(void) {
    if (_userPrivKey) { RSA_free(_userPrivKey); _userPrivKey = NULL; }
    if (_ssl)         { SSL_shutdown(_ssl); SSL_free(_ssl); _ssl = NULL; }
    if (_sslctx)      { SSL_CTX_free(_sslctx); _sslctx = NULL; }
    if (_sock >= 0)   { close(_sock); _sock = -1; }

    _hasPendingNonce   = NO;
    _pingPendingSince  = 0.0;
    _pingSeq           = 0;
    _loginTimestamp    = 0;
    _userAddress       = nil;
}

void sendClientDisconnect(void) {
    if (!isConnected()) return;
    NSLog(@"[Protocol] → Disconnect(Normal)");
    uint8_t reason = SGP_DISC_NORMAL;
    sendMsg(SGP_C_DISCONNECT, &reason, 1);
}

int connectToServer(const char *serverIP, int port, NSString *serverCert) {
    signal(SIGPIPE, SIG_IGN);
    disconnectFromServer();
    ERR_clear_error();

    // ── NOTE: SSL_library_init / SSL_load_error_strings are called
    //    exactly once at daemon startup via initOpenSSLOnce() in main.m.
    //    Do NOT call them here; they are not safe to call more than once.

    // ── TLS context ───────────────────────────────────────────────
    _sslctx = SSL_CTX_new(TLS_client_method());
    if (!_sslctx) { logSSLErrors(@"SSL_CTX_new"); return -1; }

    // Enforce TLS 1.2 minimum. Reject anything older.
    SSL_CTX_set_options(_sslctx,
        SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
        SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    // Only trust our pinned server certificate — no system CA chain.
    SSL_CTX_set_verify(_sslctx, SSL_VERIFY_PEER, NULL);

    // ── Pin the server certificate ────────────────────────────────
    if (!serverCert || [serverCert length] == 0) {
        NSLog(@"[Protocol] No server certificate provided");
        disconnectFromServer(); return -2;
    }

    BIO *bio = BIO_new_mem_buf((void *)[serverCert UTF8String], -1);
    if (!bio) { logSSLErrors(@"BIO_new"); disconnectFromServer(); return -2; }

    X509 *cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
    BIO_free(bio);
    if (!cert) {
        NSLog(@"[Protocol] Failed to parse server cert PEM");
        logSSLErrors(@"PEM_read_bio_X509");
        disconnectFromServer(); return -2;
    }

    {
        char subj[256];
        X509_NAME_oneline(X509_get_subject_name(cert), subj, sizeof(subj));
        NSLog(@"[Protocol] Pinned cert: %s", subj);
    }

    if (X509_STORE_add_cert(SSL_CTX_get_cert_store(_sslctx), cert) != 1) {
        logSSLErrors(@"X509_STORE_add_cert");
        X509_free(cert); disconnectFromServer(); return -2;
    }
    X509_free(cert);

    // ── TCP socket ────────────────────────────────────────────────
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        NSLog(@"[Protocol] socket(): %s", strerror(errno));
        disconnectFromServer(); return -3;
    }

    // ── TCP keepalive ─────────────────────────────────────────────
    // Works below TLS to detect truly stale connections (e.g. device
    // resumed from sleep while server-side FIN was lost). The
    // application-level Ping/Pong in handleMessage catches the cases
    // TCP keepalive cannot — middleboxes that forward but don't reset.
    int kv = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &kv, sizeof(kv)) < 0)
        NSLog(@"[Protocol] SO_KEEPALIVE: %s (non-fatal)", strerror(errno));
    int ki = TCP_KEEPALIVE_IDLE_SEC;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &ki, sizeof(ki)) < 0)
        NSLog(@"[Protocol] TCP_KEEPALIVE: %s (non-fatal)", strerror(errno));

    // ── Connect ───────────────────────────────────────────────────
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (inet_pton(AF_INET, serverIP, &addr.sin_addr) <= 0) {
        NSLog(@"[Protocol] inet_pton('%s') failed", serverIP);
        close(fd); disconnectFromServer(); return -4;
    }

    NSLog(@"[Protocol] Connecting to %s:%d (timeout %ds)…",
          serverIP, port, CONNECT_TIMEOUT_SEC);

    if (connectWithTimeout(fd, (struct sockaddr *)&addr,
                            sizeof(addr), CONNECT_TIMEOUT_SEC) != 0) {
        NSLog(@"[Protocol] TCP connect failed: %s (errno=%d)",
              strerror(errno), errno);
        close(fd); disconnectFromServer(); return -5;
    }

    NSLog(@"[Protocol] TCP connected, starting TLS…");

    // Short timeout only for the handshake. After success we clear it
    // so that the read loop in handleMessage can use its own select() timeout.
    struct timeval tv = { TLS_HANDSHAKE_TIMEOUT, 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    _sock = fd;

    _ssl = SSL_new(_sslctx);
    if (!_ssl) {
        logSSLErrors(@"SSL_new"); disconnectFromServer(); return -6;
    }
    SSL_set_fd(_ssl, fd);

    if (SSL_connect(_ssl) != 1) {
        int sslErr = SSL_get_error(_ssl, -1);
        NSLog(@"[Protocol] SSL_connect failed: ssl_err=%d errno=%d (%s)",
              sslErr, errno, strerror(errno));
        logSSLErrors(@"SSL_connect");
        long vr = SSL_get_verify_result(_ssl);
        if (vr != X509_V_OK)
            NSLog(@"[Protocol] Cert verify: %ld (%s)",
                  vr, X509_verify_cert_error_string(vr));
        X509 *peer = SSL_get_peer_certificate(_ssl);
        if (peer) {
            char subj[256];
            X509_NAME_oneline(X509_get_subject_name(peer), subj, sizeof(subj));
            NSLog(@"[Protocol] Peer cert subject: %s", subj);
            X509_free(peer);
        } else {
            NSLog(@"[Protocol] Server presented NO cert");
        }
        disconnectFromServer(); return -7;
    }

    NSLog(@"[Protocol] TLS OK: %s  cipher: %s",
          SSL_get_version(_ssl), SSL_get_cipher(_ssl));

    // Clear handshake timeouts — handleMessage drives its own deadline
    // via select().
    tv.tv_sec = 0; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    NSLog(@"[Protocol] Connected to %s:%d", serverIP, port);
    return 0;
}

void startLogin(NSString *address, RSA *privKey, NSString *language) {
    (void)language;   // v2: language derived server-side from stored profile

    if (_userPrivKey) { RSA_free(_userPrivKey); _userPrivKey = NULL; }

    _userAddress    = address;
    _userPrivKey    = privKey;   // ownership taken
    _loginTimestamp = (int64_t)time(NULL);

    // Payload: addr_len[2] + addr[N] + timestamp[8] + proto_version[4]
    const char *addrUTF8 = [address UTF8String];
    uint16_t addrLen16 = (uint16_t)MIN(strlen(addrUTF8), (size_t)0xFFFF);

    NSMutableData *p = [NSMutableData data];
    uint8_t addrLenBE[2]; encodeBEUInt16(addrLen16, addrLenBE);
    [p appendBytes:addrLenBE length:2];
    [p appendBytes:addrUTF8  length:addrLen16];
    uint8_t tsBE[8]; encodeBEInt64(_loginTimestamp, tsBE);
    [p appendBytes:tsBE length:8];
    uint32_t verBE = htonl(SGP_VERSION);
    [p appendBytes:&verBE length:4];

    sendMsg(SGP_C_LOGIN, [p bytes], (uint32_t)[p length]);
}

void ackNotification(NSData *msgID, int status) {
    if (!msgID || [msgID length] != SGP_MSG_ID_LEN) {
        NSLog(@"[Protocol] ackNotification: bad msg_id length %lu",
              (unsigned long)[msgID length]);
        return;
    }
    uint8_t payload[SGP_MSG_ID_LEN + 1];
    memcpy(payload, [msgID bytes], SGP_MSG_ID_LEN);
    payload[SGP_MSG_ID_LEN] = (uint8_t)status;
    sendMsg(SGP_C_ACK, payload, sizeof(payload));
}

BOOL registerDeviceToken(NSData *routingKey, NSString *bundleId) {
    if (!routingKey || [routingKey length] != SGP_ROUTING_KEY_LEN || !bundleId)
        return NO;
    if (!isConnected()) {
        NSLog(@"[Protocol] registerDeviceToken: not connected");
        return NO;
    }

    dispatch_once(&_tokenWaitersOnce, ^{
        _tokenWaiters = [[NSMutableDictionary alloc] init];
    });

    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    @synchronized(_tokenWaiters) { _tokenWaiters[bundleId] = sema; }

    // Payload: routing_key[32] + bundle_id_len[2] + bundle_id[N]
    const char *bidUTF8  = [bundleId UTF8String];
    uint16_t    bidLen16 = (uint16_t)MIN(strlen(bidUTF8), (size_t)0xFFFF);

    NSMutableData *payload = [NSMutableData data];
    [payload appendData:routingKey];
    uint8_t bidLenBE[2]; encodeBEUInt16(bidLen16, bidLenBE);
    [payload appendBytes:bidLenBE length:2];
    [payload appendBytes:bidUTF8  length:bidLen16];

    BOOL sent = (sendMsg(SGP_C_REG_TOKEN,
                         [payload bytes],
                         (uint32_t)[payload length]) == 0);
    if (!sent) {
        @synchronized(_tokenWaiters) { [_tokenWaiters removeObjectForKey:bundleId]; }
#if !__has_feature(objc_arc)
        dispatch_release(sema);
#endif
        return NO;
    }

    long rc = dispatch_semaphore_wait(
        sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
    @synchronized(_tokenWaiters) { [_tokenWaiters removeObjectForKey:bundleId]; }
#if !__has_feature(objc_arc)
    dispatch_release(sema);
#endif
    return (rc == 0);
}

void sendFeedback(NSData *routingKey, NSNumber *type, NSString *reason) {
    if (!routingKey || [routingKey length] != SGP_ROUTING_KEY_LEN) return;

    const char *reasonUTF8 = reason ? [reason UTF8String] : "";
    uint16_t    reasonLen  = (uint16_t)MIN(strlen(reasonUTF8), (size_t)0xFFFF);

    // Payload: routing_key[32] + type[1] + reason_len[2] + reason[N]
    NSMutableData *payload = [NSMutableData data];
    [payload appendData:routingKey];
    uint8_t t = (uint8_t)[type unsignedIntegerValue];
    [payload appendBytes:&t length:1];
    uint8_t rLenBE[2]; encodeBEUInt16(reasonLen, rLenBE);
    [payload appendBytes:rLenBE    length:2];
    [payload appendBytes:reasonUTF8 length:reasonLen];

    sendMsg(SGP_C_FEEDBACK, [payload bytes], (uint32_t)[payload length]);
}

/* ─────────────────────────────────────────────────────────────────
 * handleMessage
 *
 * Called in a tight loop by the connection loop thread. Blocks until
 * one message arrives (or the Ping timeout fires), then dispatches it.
 *
 * Ping/Pong state machine
 * ────────────────────────
 * select() is given a timeout of SGP_PING_INTERVAL_SEC normally.
 * When a Ping is outstanding the timeout is clamped to the remaining
 * Pong window so we detect expiry promptly.
 *
 *   Timeout with no pending Ping → send Ping, record time, return OK.
 *   Timeout with pending Ping    → check elapsed:
 *       ≥ SGP_PONG_TIMEOUT_SEC → return SGP_ERR_TIMEOUT.
 *       <  SGP_PONG_TIMEOUT_SEC → return OK (will recheck next call).
 *   Data arrives → reset idle timer, read + dispatch one message.
 * ───────────────────────────────────────────────────────────────── */

int handleMessage(void) {
    if (!isConnected()) return SGP_ERR_IO;

    // ── select() with appropriate timeout ────────────────────────
    {
        long waitSec = SGP_PING_INTERVAL_SEC;

        if (_pingPendingSince > 0.0) {
            double elapsed = monotonicSec() - _pingPendingSince;
            if (elapsed >= (double)SGP_PONG_TIMEOUT_SEC) {
                NSLog(@"[Protocol] Pong timeout after %.1fs — dead connection", elapsed);
                return SGP_ERR_TIMEOUT;
            }
            long remaining = SGP_PONG_TIMEOUT_SEC - (long)elapsed;
            waitSec = MAX(remaining, 1L);
        }

        fd_set rfds; FD_ZERO(&rfds); FD_SET(_sock, &rfds);
        struct timeval tv = { waitSec, 0 };
        int sel = select(_sock + 1, &rfds, NULL, NULL, &tv);

        if (sel < 0) {
            if (errno == EINTR) return SGP_OK;
            NSLog(@"[Protocol] select(): %s", strerror(errno));
            return SGP_ERR_IO;
        }

        if (sel == 0) {
            // Timeout — no data received.
            if (_pingPendingSince > 0.0) {
                // Outstanding Ping; timeout window not fully elapsed yet
                // (we'd have caught it above if it had). Recheck next call.
                return SGP_OK;
            }
            NSLog(@"[Protocol] Idle for %lds — sending Ping", waitSec);
            if (sendPing() != 0) {
                NSLog(@"[Protocol] Failed to send Ping");
                return SGP_ERR_IO;
            }
            return SGP_OK;
        }
        // sel > 0: socket is readable — fall through.
    }

    // ── Read the 8-byte header ────────────────────────────────────
    uint8_t hdr[SGP_HEADER_SIZE];
    if (sslReadExact(hdr, SGP_HEADER_SIZE) != 0) {
        NSLog(@"[Protocol] Failed to read header");
        return SGP_ERR_IO;
    }

    if (hdr[0] != SGP_MAGIC) {
        NSLog(@"[Protocol] Bad magic 0x%02X (expected 0x%02X)", hdr[0], SGP_MAGIC);
        return SGP_ERR_PROTO;
    }
    if (hdr[1] != SGP_VERSION) {
        NSLog(@"[Protocol] Unsupported version 0x%02X (we speak 0x%02X)",
              hdr[1], SGP_VERSION);
        return SGP_ERR_PROTO;
    }

    SGPMsgType msgType = (SGPMsgType)hdr[2];
    // hdr[3] = flags — reserved; ignore unknown bits for forward compat.

    uint32_t payloadLen;
    memcpy(&payloadLen, hdr + 4, 4);
    payloadLen = ntohl(payloadLen);

    if (payloadLen > SGP_MAX_PAYLOAD_LEN) {
        NSLog(@"[Protocol] Payload too large: %u bytes", payloadLen);
        return SGP_ERR_PROTO;
    }

    // ── Read payload ──────────────────────────────────────────────
    uint8_t *raw = NULL;
    if (payloadLen > 0) {
        raw = malloc(payloadLen);
        if (!raw) return SGP_ERR_IO;
        if (sslReadExact(raw, (int)payloadLen) != 0) {
            NSLog(@"[Protocol] Failed to read %u-byte payload", payloadLen);
            free(raw);
            return SGP_ERR_IO;
        }
    }
    const uint8_t *p = raw;

    // Any data from the server clears the outstanding Ping timer.
    _pingPendingSince = 0.0;

    NSLog(@"[Protocol] ← type=0x%02X len=%u", (unsigned)msgType, payloadLen);

    int result = SGP_OK;

    switch (msgType) {

    /* ── SGP_S_HELLO ─────────────────────────────────────────────── */
    case SGP_S_HELLO: {
        uint32_t serverVer = 0;
        if (payloadLen >= 4) { memcpy(&serverVer, p, 4); serverVer = ntohl(serverVer); }
        NSLog(@"[Protocol] Hello: server version=%u", serverVer);
        if (!_delegate) { result = SGP_ERR_PROTO; break; }
        [_delegate handleWelcomeMessage];
        break;
    }

    /* ── SGP_S_CHALLENGE ─────────────────────────────────────────── */
    case SGP_S_CHALLENGE: {
        if (payloadLen != SGP_NONCE_LEN) {
            NSLog(@"[Protocol] Challenge: wrong nonce length %u", payloadLen);
            result = SGP_ERR_PROTO; break;
        }
        memcpy(_pendingNonce, p, SGP_NONCE_LEN);
        _hasPendingNonce = YES;
        if (sendLoginResponse() != 0) {
            NSLog(@"[Protocol] Failed to send login response");
            result = SGP_ERR_AUTH;
        }
        break;
    }

    /* ── SGP_S_AUTH_OK ───────────────────────────────────────────── */
    case SGP_S_AUTH_OK: {
        NSLog(@"[Protocol] Authenticated");
        if (_delegate) [_delegate authenticationSuccessful];
        sendMsg(SGP_C_POLL, NULL, 0);   // drain offline queue
        break;
    }

    /* ── SGP_S_NOTIFY ────────────────────────────────────────────── */
    case SGP_S_NOTIFY: {
        // Minimum prefix: routing_key[32]+msg_id[16]+flags[1]+data_len[4] = 53
        if (payloadLen < 53) {
            NSLog(@"[Protocol] Notify: payload too short (%u)", payloadLen);
            result = SGP_ERR_PROTO; break;
        }
        if (!_delegate) { result = SGP_ERR_PROTO; break; }

        NSData *routingKey = [NSData dataWithBytes:p      length:SGP_ROUTING_KEY_LEN];
        NSData *msgID      = [NSData dataWithBytes:p + 32 length:SGP_MSG_ID_LEN];

        uint8_t flags    = p[48];
        BOOL isEncrypted = (flags & 0x01) != 0;
        BOOL isJSON      = (flags & 0x02) != 0;

        uint32_t dataLen;
        memcpy(&dataLen, p + 49, 4);
        dataLen = ntohl(dataLen);

        uint32_t cursor = 53;
        if ((uint64_t)cursor + dataLen > payloadLen) {
            NSLog(@"[Protocol] Notify: data_len %u overruns payload", dataLen);
            result = SGP_ERR_PROTO; break;
        }

        NSData *data = [NSData dataWithBytes:p + cursor length:dataLen];
        cursor += dataLen;

        NSData *iv = nil;
        if (isEncrypted) {
            if (cursor + SGP_GCM_IV_LEN > payloadLen) {
                NSLog(@"[Protocol] Notify: IV truncated");
                result = SGP_ERR_PROTO; break;
            }
            iv = [NSData dataWithBytes:p + cursor length:SGP_GCM_IV_LEN];
        }

        NSMutableDictionary *notif = [NSMutableDictionary dictionaryWithObjectsAndKeys:
            routingKey,                     @"routing_key",
            msgID,                          @"msg_id",
            @(isEncrypted),                 @"is_encrypted",
            isJSON ? @"json" : @"plist",    @"data_type",
            data,                           @"data",
            nil];
        if (iv) notif[@"iv"] = iv;

        [_delegate processNotificationMessage:notif];
        break;
    }

    /* ── SGP_S_DISCONNECT ────────────────────────────────────────── */
    case SGP_S_DISCONNECT: {
        uint8_t reason = (payloadLen >= 1) ? p[0] : SGP_DISC_NORMAL;
        NSLog(@"[Protocol] Server disconnect reason=0x%02X", reason);
        result = (reason == SGP_DISC_AUTH_FAIL) ? SGP_ERR_AUTH : SGP_ERR_CLOSED;
        break;
    }

    /* ── SGP_S_TOKEN_ACK ─────────────────────────────────────────── */
    case SGP_S_TOKEN_ACK: {
        // routing_key[32] + bundle_id_len[2] + bundle_id[N]
        if (payloadLen < 34) { result = SGP_ERR_PROTO; break; }
        uint16_t bidLen; memcpy(&bidLen, p + 32, 2); bidLen = ntohs(bidLen);
        if ((uint32_t)34 + bidLen > payloadLen) { result = SGP_ERR_PROTO; break; }

        NSString *bundleId = [[NSString alloc] initWithBytes:p + 34
                                                       length:bidLen
                                                     encoding:NSUTF8StringEncoding];
        if (!bundleId) { result = SGP_ERR_PROTO; break; }

        dispatch_once(&_tokenWaitersOnce, ^{
            _tokenWaiters = [[NSMutableDictionary alloc] init];
        });
        dispatch_semaphore_t sema = nil;
        @synchronized(_tokenWaiters) { sema = _tokenWaiters[bundleId]; }
        if (sema) dispatch_semaphore_signal(sema);

        if (_delegate && [_delegate respondsToSelector:
                @selector(deviceTokenRegistrationCompleted:)])
            [_delegate deviceTokenRegistrationCompleted:bundleId];

        [bundleId release];
        break;
    }

    /* ── SGP_S_PONG ──────────────────────────────────────────────── */
    case SGP_S_PONG: {
        // _pingPendingSince already cleared above on any received data.
        if (payloadLen == SGP_PING_SEQ_LEN) {
            uint64_t seq = 0;
            for (int i = 0; i < 8; i++) seq = (seq << 8) | p[i];
            NSLog(@"[Protocol] ← Pong seq=%llu", (unsigned long long)seq);
        }
        break;
    }

    /* ── Unknown ─────────────────────────────────────────────────── */
    default:
        // Silently ignore unknown types for forward compatibility.
        // A newer server may introduce types the client doesn't know yet.
        NSLog(@"[Protocol] Unknown type 0x%02X (%u bytes) — ignoring",
              (unsigned)msgType, payloadLen);
        break;
    }

    free(raw);
    return result;
}