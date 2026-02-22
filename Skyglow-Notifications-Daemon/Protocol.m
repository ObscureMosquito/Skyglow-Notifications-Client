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
#import "Globals.h"
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
#include <mach/mach_time.h>

/* ─────────────────────────────────────────────────────────────────
 * Connection timeouts
 * ───────────────────────────────────────────────────────────────── */

#define CONNECT_TIMEOUT_SEC     10
#define TLS_HANDSHAKE_TIMEOUT   15
#define TCP_KEEPALIVE_IDLE_SEC  60

/* ─────────────────────────────────────────────────────────────────
 * File-private connection state
 * ───────────────────────────────────────────────────────────────── */

static id<NotificationDelegate>  _delegate   = nil;

static SSL     *_ssl    = NULL;
static SSL_CTX *_sslctx = NULL;
static int      _sock   = -1;

/// Serialises all SSL_write calls.
static pthread_mutex_t  _sendLock = PTHREAD_MUTEX_INITIALIZER;

static NSString *_userAddress    = nil;
static RSA      *_userPrivKey    = NULL;
static int64_t   _loginTimestamp = 0;

static uint8_t   _pendingNonce[SGP_NONCE_LEN];
static BOOL      _hasPendingNonce = NO;

static uint64_t  _pingSeq = 0;
static double    _pingPendingSince = 0.0;

/// retry_after from the most recent S_DISCONNECT payload.
/// 0 until a disconnect is received; then holds the server's hint.
static uint32_t  _lastDisconnRetryAfter = 0;

/// Registration state — held between startRegistration() and S_REGISTER_OK/FAIL.
/// _regPendingAddress is the UUID address we proposed in C_REGISTER.
/// _regPendingPrivKey is the freshly-generated RSA key (PEM) to persist on success.
/// Both are cleared when registration completes or fails.
static NSString *_regPendingAddress  = nil;
static NSString *_regPendingPrivKey  = nil;
static RSA      *_regPendingRSA      = NULL;   // used to sign C_REGISTER_RESP
static int64_t   _regTimestamp       = 0;

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

/// Monotonic clock in seconds using mach_absolute_time().
/// Immune to NTP / wall-clock adjustments — safe for Ping RTT.
static double monotonicSec(void) {
    static mach_timebase_info_data_t tb;
    static dispatch_once_t           onceToken;
    dispatch_once(&onceToken, ^{ mach_timebase_info(&tb); });
    uint64_t ticks = mach_absolute_time();
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

static int64_t decodeBEInt64(const uint8_t p[8]) {
    uint64_t u = 0;
    for (int i = 0; i < 8; i++) u = (u << 8) | p[i];
    return (int64_t)u;
}

/* ─────────────────────────────────────────────────────────────────
 * SSL I/O — reads (single-threaded; no lock needed)
 * ───────────────────────────────────────────────────────────────── */

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
    frame[3] = 0x00;  // header flags — reserved

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
    fcntl(fd, F_SETFL, flags);

    if (rc == 0) { NSLog(@"[Protocol] connect() timed out after %ds", timeoutSec); errno = ETIMEDOUT; return -1; }
    if (rc < 0)  { NSLog(@"[Protocol] select() on connect: %s", strerror(errno)); return -1; }

    int soErr = 0; socklen_t soErrLen = sizeof(soErr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soErr, &soErrLen) < 0) return -1;
    if (soErr != 0) {
        NSLog(@"[Protocol] connect() deferred error: %s (errno=%d)", strerror(soErr), soErr);
        errno = soErr;
        return -1;
    }
    return 0;
}

/* ─────────────────────────────────────────────────────────────────
 * sendLoginResponse  (called from handleMessage on SGP_S_CHALLENGE)
 *
 * Signs: nonce[32] || device_address_utf8 || login_timestamp_be[8]
 * using RSA-PSS-SHA256.
 * Sends SGP_C_LOGIN_RESP: timestamp[8] + sig_len[2] + sig[N].
 * ───────────────────────────────────────────────────────────────── */

/* ─────────────────────────────────────────────────────────────────
 * signPSS_SHA256  —  RSA-PSS-SHA256 using the low-level RSA API.
 *
 * Why not EVP_DigestSign*?
 *   The EVP_DigestSign path works correctly on desktop OpenSSL 1.1+, but
 *   on embedded iOS OpenSSL builds (which are often static libraries compiled
 *   from source against the iOS SDK) the internal PKEY method table for RSA
 *   signing may not be initialised until a higher-level operation triggers it.
 *   This causes a NULL dereference inside EVP_DigestSignInit or the subsequent
 *   EVP_PKEY_CTX_set_rsa_padding call, presenting as a segfault.
 *
 * The low-level path is stable on every OpenSSL version ≥ 0.9.8:
 *   1. SHA-256 the message with EVP_Digest (plain hash, no signing context).
 *   2. Apply PKCS#1 PSS padding into a buffer the size of the RSA modulus.
 *   3. Raw-encrypt the padded buffer with RSA_private_encrypt(RSA_NO_PADDING).
 *
 * The Java server verifies with RSASSA-PSS / SHA-256 / MGF1-SHA-256 / saltLen=32,
 * which is exactly what step 2 produces with RSA_PSS_SALTLEN_DIGEST (= hashLen = 32).
 *
 * Returns a malloc'd signature buffer of *outLen bytes, or NULL on error.
 * Caller must free().
 * ───────────────────────────────────────────────────────────────── */
static uint8_t *signPSS_SHA256(RSA *rsa,
                                const uint8_t *data1, size_t data1Len,
                                const uint8_t *data2, size_t data2Len,
                                const uint8_t *data3, size_t data3Len,
                                size_t *outLen) {
    // 1. SHA-256 over up to three message parts.
    uint8_t digest[32];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return NULL;
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
        (data1Len > 0 && EVP_DigestUpdate(mdctx, data1, data1Len) != 1) ||
        (data2Len > 0 && EVP_DigestUpdate(mdctx, data2, data2Len) != 1) ||
        (data3Len > 0 && EVP_DigestUpdate(mdctx, data3, data3Len) != 1) ||
        EVP_DigestFinal_ex(mdctx, digest, NULL) != 1) {
        logSSLErrors(@"EVP_Digest");
        EVP_MD_CTX_free(mdctx);
        return NULL;
    }
    EVP_MD_CTX_free(mdctx);

    // 2. PSS padding then raw private encrypt.
    int rsaSize = RSA_size(rsa);
    uint8_t *em = malloc(rsaSize);
    if (!em) return NULL;
    if (RSA_padding_add_PKCS1_PSS_mgf1(rsa, em, digest,
                                        EVP_sha256(), EVP_sha256(),
                                        -1) != 1) {
        logSSLErrors(@"RSA_padding_add_PKCS1_PSS_mgf1");
        free(em);
        return NULL;
    }

    uint8_t *sig = malloc(rsaSize);
    if (!sig) { free(em); return NULL; }
    int sigLen = RSA_private_encrypt(rsaSize, em, sig, rsa, RSA_NO_PADDING);
    free(em);
    if (sigLen < 0) {
        logSSLErrors(@"RSA_private_encrypt");
        free(sig);
        return NULL;
    }
    *outLen = (size_t)sigLen;
    return sig;
}

/* Build and send a challenge response frame.
 * msgType is either SGP_C_LOGIN_RESP or SGP_C_REGISTER_RESP.
 * address is the device address included in the signed data.
 * timestamp is the session timestamp to echo in the payload.
 */
static int sendChallengeResponse(SGPMsgType msgType,
                                  RSA *rsa,
                                  NSString *address,
                                  int64_t timestamp) {
    const char *addrUTF8 = [address UTF8String];
    size_t addrLen = strlen(addrUTF8);
    uint8_t tsBE[8]; encodeBEInt64(timestamp, tsBE);

    // Sign: nonce[32] || device_address_utf8 || timestamp_be[8]
    size_t sigLen = 0;
    uint8_t *sig = signPSS_SHA256(rsa,
                                   _pendingNonce, SGP_NONCE_LEN,
                                   (const uint8_t *)addrUTF8, addrLen,
                                   tsBE, 8,
                                   &sigLen);
    _hasPendingNonce = NO;   // consume nonce regardless of signing outcome

    if (!sig) {
        NSLog(@"[Protocol] signPSS_SHA256 failed");
        return -1;
    }
    if (sigLen > 0xFFFF) {
        NSLog(@"[Protocol] Signature too long (%zu bytes)", sigLen);
        free(sig); return -1;
    }

    // Payload: timestamp[8] + sig_len[2] + sig[N]
    size_t payloadLen = 8 + 2 + sigLen;
    uint8_t *payload  = malloc(payloadLen);
    if (!payload) { free(sig); return -1; }
    memcpy(payload, tsBE, 8);
    uint8_t slBE[2]; encodeBEUInt16((uint16_t)sigLen, slBE);
    memcpy(payload + 8,  slBE, 2);
    memcpy(payload + 10, sig, sigLen);
    free(sig);

    int rc = sendMsg(msgType, payload, (uint32_t)payloadLen);
    free(payload);
    return rc;
}

static int sendLoginResponse(void) {
    if (!_hasPendingNonce || !_userAddress || !_userPrivKey) {
        NSLog(@"[Protocol] sendLoginResponse: missing state");
        return -1;
    }
    NSLog(@"[Protocol] → C_LOGIN_RESP");
    return sendChallengeResponse(SGP_C_LOGIN_RESP,
                                  _userPrivKey,
                                  _userAddress,
                                  _loginTimestamp);
}

/* ─────────────────────────────────────────────────────────────────
 * Client-initiated Ping helper
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
 * Registration helpers
 *
 * APNS-style first-time device setup:
 *
 *   Client                              Server
 *   ──────                              ──────
 *   C_REGISTER ──────────────────────>  (addr_len[2]+addr + key_len[2]+pubDER
 *                                        + timestamp[8] + proto_ver[4])
 *              <──────────────────────  S_CHALLENGE  (nonce[32])
 *   C_REGISTER_RESP ────────────────>   (timestamp[8] + sig_len[2] + sig[N])
 *              <──────────────────────  S_REGISTER_OK  (proto_ver[4])
 *                                       [server resets to CONNECTED state]
 *   C_LOGIN ─────────────────────────>  proceed with normal auth immediately
 *
 * The client picks the device_address: a UUID v4 generated with
 * SecRandomCopyBytes. This is the same pattern used by APNS device tokens —
 * the device generates its own identity rather than waiting for the server
 * to assign one.
 *
 * The signed data for C_REGISTER_RESP is identical to C_LOGIN_RESP:
 *   nonce[32] || device_address_utf8 || timestamp_be[8]
 * The server verifies with the public key included in C_REGISTER, then
 * stores it. All subsequent logins use the same key material.
 *
 * The RSA keypair (2048-bit) is generated fresh for each registration
 * attempt. If registration fails or the connection drops mid-flow, a new
 * attempt will generate a new keypair — there's no value in reusing a
 * key that may have been seen by a failing server.
 * ───────────────────────────────────────────────────────────────── */

/// Generate a UUID v4 string from 16 random bytes via SecRandomCopyBytes.
/// Format: "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx" (36 chars, lowercase).
static NSString *generateUUIDAddress(void) {
    uint8_t bytes[16];
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(bytes), bytes) != errSecSuccess) {
        NSLog(@"[Protocol] SecRandomCopyBytes failed for UUID generation");
        return nil;
    }
    // Set version 4 bits
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    // Set variant bits (10xxxxxx)
    bytes[8] = (bytes[8] & 0x3F) | 0x80;

    return [NSString stringWithFormat:
        @"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0],  bytes[1],  bytes[2],  bytes[3],
        bytes[4],  bytes[5],
        bytes[6],  bytes[7],
        bytes[8],  bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]];
}

/// Send SGP_C_REGISTER.
/// Generates a fresh RSA-2048 keypair, proposes a UUID device address,
/// stores pending state for use in sendRegisterResponse() and on S_REGISTER_OK.
/// Returns the proposed address, or nil on any failure.
NSString *startRegistration(void) {
    if (!isConnected()) {
        NSLog(@"[Protocol] startRegistration: not connected");
        return nil;
    }

    // Clean up any previous attempt.
    if (_regPendingRSA) { RSA_free(_regPendingRSA); _regPendingRSA = NULL; }
    [_regPendingAddress release]; _regPendingAddress = nil;
    [_regPendingPrivKey release]; _regPendingPrivKey = nil;

    // ── 1. Generate RSA-2048 keypair ──────────────────────────────
    BIGNUM *bn = BN_new();
    if (!bn) return nil;
    BN_set_word(bn, RSA_F4);

    RSA *rsa = RSA_new();
    if (!rsa) { BN_free(bn); return nil; }

    if (RSA_generate_key_ex(rsa, 2048, bn, NULL) != 1) {
        logSSLErrors(@"RSA_generate_key_ex");
        RSA_free(rsa); BN_free(bn);
        return nil;
    }
    BN_free(bn);

    // ── 2. Encode private key as PEM (for persistence on success) ──
    BIO *privBio = BIO_new(BIO_s_mem());
    if (!privBio || PEM_write_bio_RSAPrivateKey(privBio, rsa, NULL, NULL, 0, NULL, NULL) != 1) {
        logSSLErrors(@"PEM_write_bio_RSAPrivateKey");
        if (privBio) BIO_free(privBio);
        RSA_free(rsa);
        return nil;
    }
    long privLen = BIO_pending(privBio);
    char *privBuf = malloc(privLen + 1);
    if (!privBuf) { BIO_free(privBio); RSA_free(rsa); return nil; }
    BIO_read(privBio, privBuf, (int)privLen);
    privBuf[privLen] = '\0';
    BIO_free(privBio);
    NSString *privKeyPEM = [NSString stringWithUTF8String:privBuf];
    free(privBuf);

    // ── 3. Encode public key as SubjectPublicKeyInfo DER ──────────
    // Server uses X509EncodedKeySpec (= SubjectPublicKeyInfo DER).
    // i2d_RSA_PUBKEY writes exactly that format.
    uint8_t *pubDer = NULL;
    int pubDerLen = i2d_RSA_PUBKEY(rsa, &pubDer);
    if (pubDerLen <= 0 || !pubDer) {
        logSSLErrors(@"i2d_RSA_PUBKEY");
        RSA_free(rsa);
        return nil;
    }

    // ── 4. Generate UUID device address ───────────────────────────
    NSString *address = generateUUIDAddress();
    if (!address) {
        OPENSSL_free(pubDer);
        RSA_free(rsa);
        return nil;
    }

    // ── 5. Build C_REGISTER payload ───────────────────────────────
    // addr_len[2] + addr[N] + key_len[2] + pubDER[N] + timestamp[8] + proto_ver[4]
    const char *addrUTF8 = [address UTF8String];
    uint16_t addrLen16 = (uint16_t)MIN(strlen(addrUTF8), (size_t)0xFFFF);

    _regTimestamp = (int64_t)time(NULL);
    uint8_t tsBE[8]; encodeBEInt64(_regTimestamp, tsBE);

    NSMutableData *payload = [NSMutableData data];
    uint8_t addrLenBE[2]; encodeBEUInt16(addrLen16, addrLenBE);
    [payload appendBytes:addrLenBE length:2];
    [payload appendBytes:addrUTF8 length:addrLen16];

    if (pubDerLen > 0xFFFF) {
        NSLog(@"[Protocol] Public key DER too large (%d bytes)", pubDerLen);
        OPENSSL_free(pubDer); RSA_free(rsa); return nil;
    }
    uint8_t keyLenBE[2]; encodeBEUInt16((uint16_t)pubDerLen, keyLenBE);
    [payload appendBytes:keyLenBE length:2];
    [payload appendBytes:pubDer length:pubDerLen];
    OPENSSL_free(pubDer);

    [payload appendBytes:tsBE length:8];
    uint32_t verBE = htonl(SGP_VERSION);
    [payload appendBytes:&verBE length:4];

    // ── 6. Load a clean RSA object from PEM for signing ─────────
    // We free the original keygen RSA and reload from the PEM we just encoded.
    // This guarantees a fully-initialized RSA object (blinding state, CRT params,
    // BN pool) regardless of how the underlying OpenSSL build handles freshly
    // generated vs. PEM-loaded keys. The keygen RSA may have been modified
    // internally by i2d_RSA_PUBKEY; the PEM-loaded copy is always clean.
    RSA_free(rsa);
    rsa = NULL;

    BIO *reloadBio = BIO_new_mem_buf((void *)[privKeyPEM UTF8String], -1);
    RSA *rsaForSigning = reloadBio
        ? PEM_read_bio_RSAPrivateKey(reloadBio, NULL, NULL, NULL)
        : NULL;
    if (reloadBio) BIO_free(reloadBio);

    if (!rsaForSigning) {
        logSSLErrors(@"PEM_read_bio_RSAPrivateKey (reload)");
        // pubDer was already freed above (appended to payload then released).
        return nil;
    }

    // ── 7. Stash state and send ───────────────────────────────────
    _regPendingAddress = [address retain];
    _regPendingPrivKey = [privKeyPEM retain];
    _regPendingRSA     = rsaForSigning;   // PEM-loaded, clean, owned by us

    if (sendMsg(SGP_C_REGISTER, [payload bytes], (uint32_t)[payload length]) != 0) {
        NSLog(@"[Protocol] Failed to send C_REGISTER");
        RSA_free(_regPendingRSA); _regPendingRSA = NULL;
        [_regPendingAddress release]; _regPendingAddress = nil;
        [_regPendingPrivKey release]; _regPendingPrivKey = nil;
        return nil;
    }

    NSLog(@"[Protocol] → C_REGISTER addr=%@ (key %d bytes)", address, pubDerLen);
    return address;
}

static int sendRegisterResponse(void) {
    if (!_hasPendingNonce || !_regPendingAddress || !_regPendingRSA) {
        NSLog(@"[Protocol] sendRegisterResponse: missing registration state");
        return -1;
    }
    NSLog(@"[Protocol] → C_REGISTER_RESP");
    return sendChallengeResponse(SGP_C_REGISTER_RESP,
                                  _regPendingRSA,
                                  _regPendingAddress,
                                  _regTimestamp);
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

    _hasPendingNonce        = NO;
    _pingPendingSince       = 0.0;
    _pingSeq                = 0;
    _loginTimestamp         = 0;
    [_userAddress release]; _userAddress = nil;

    // Clear any in-progress registration state.
    [_regPendingAddress release]; _regPendingAddress = nil;
    [_regPendingPrivKey release]; _regPendingPrivKey = nil;
    if (_regPendingRSA) { RSA_free(_regPendingRSA); _regPendingRSA = NULL; }
    _regTimestamp      = 0;

    // Do not reset _lastDisconnRetryAfter here — main.m reads it
    // after disconnectFromServer returns.
}

void sendClientDisconnect(void) {
    if (!isConnected()) return;
    NSLog(@"[Protocol] → Disconnect(Normal)");
    uint8_t reason = SGP_DISC_NORMAL;
    sendMsg(SGP_C_DISCONNECT, &reason, 1);
}

uint32_t getLastDisconnRetryAfter(void) {
    return _lastDisconnRetryAfter;
}

int connectToServer(const char *serverIP, int port, NSString *serverCert) {
    signal(SIGPIPE, SIG_IGN);
    _lastDisconnRetryAfter = 0;   // reset for this new connection attempt
    disconnectFromServer();
    ERR_clear_error();

    // ── TLS context ───────────────────────────────────────────────
    _sslctx = SSL_CTX_new(TLS_client_method());
    if (!_sslctx) { logSSLErrors(@"SSL_CTX_new"); return -1; }

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

    // ── Baseband Offload (Wake-on-Wireless) ───────────────────────
    #ifndef SO_TRAFFIC_CLASS
    #define SO_TRAFFIC_CLASS 0x1086
    #endif
    #ifndef SO_TC_BK_SYS
    #define SO_TC_BK_SYS 0x100
    #endif

    int tc = SO_TC_BK_SYS; // "Background System" priority
    if (setsockopt(fd, SOL_SOCKET, SO_TRAFFIC_CLASS, &tc, sizeof(tc)) < 0) {
        NSLog(@"[Protocol] SO_TRAFFIC_CLASS: %s (non-fatal)", strerror(errno));
    }

    // ── TCP keepalive ─────────────────────────────────────────────
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
        NSLog(@"[Protocol] TCP connect failed: %s (errno=%d)", strerror(errno), errno);
        close(fd); disconnectFromServer(); return -5;
    }

    NSLog(@"[Protocol] TCP connected, starting TLS…");

    struct timeval tv = { TLS_HANDSHAKE_TIMEOUT, 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    _sock = fd;

    _ssl = SSL_new(_sslctx);
    if (!_ssl) { logSSLErrors(@"SSL_new"); disconnectFromServer(); return -6; }
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

    // Clear handshake timeouts — handleMessage drives its own deadline via select().
    tv.tv_sec = 0; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    NSLog(@"[Protocol] Connected to %s:%d", serverIP, port);
    return 0;
}

void startLogin(NSString *address, RSA *privKey, NSString *language) {
    (void)language;   // language derived server-side from stored profile

    if (_userPrivKey) { RSA_free(_userPrivKey); _userPrivKey = NULL; }

    _userAddress    = [address retain];
    _userPrivKey    = privKey;
    _loginTimestamp = (int64_t)time(NULL);

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
        NSLog(@"[Protocol] ackNotification: bad msg_id length");
        return;
    }
    
    // 1. Save it to the database so it survives crashes/disconnects
    [db queueAckForMsgID:msgID status:status];
    
    // 2. Try to flush immediately
    flushPendingACKs();
}

void flushPendingACKs(void) {
    if (!isConnected()) return;
    
    NSArray *pending = [db pendingAcks];
    if ([pending count] == 0) return;
    
    NSLog(@"[Protocol] Flushing %lu pending ACKs to server...", (unsigned long)[pending count]);
    
    for (NSDictionary *ack in pending) {
        NSData *msgID = ack[@"msgID"];
        int status = [ack[@"status"] intValue];
        
        uint8_t payload[SGP_MSG_ID_LEN + 1];
        memcpy(payload, [msgID bytes], SGP_MSG_ID_LEN);
        payload[SGP_MSG_ID_LEN] = (uint8_t)status;
        
        // Write to socket
        if (sendMsg(SGP_C_ACK, payload, sizeof(payload)) == 0) {
            // Success! Remove from database
            [db removeAckForMsgID:msgID];
        } else {
            // Socket broke mid-flush. Stop trying; they will remain in the DB.
            NSLog(@"[Protocol] Socket broken while flushing ACKs. Will retry on next connect.");
            break; 
        }
    }
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

void flushActiveTopicFilter(void) {
    if (!isConnected()) return;
    
    NSArray *keys = [db allActiveRoutingKeys];
    NSUInteger totalKeys = [keys count];
    
    // Max payload = 4096. Minus 3 bytes for Flags & Count = 4093 bytes available.
    // 4093 / 32 bytes per key = 127 keys maximum per chunk.
    NSUInteger maxKeysPerChunk = (SGP_MAX_PAYLOAD_LEN - 3) / SGP_ROUTING_KEY_LEN;
    NSUInteger offset = 0;
    
    NSLog(@"[Protocol] Flushing topic filter (%lu total active apps)...", (unsigned long)totalKeys);
    
    // We use a do-while loop so that if totalKeys == 0, we still send ONE packet
    // with count=0. This tells the server "I have zero apps installed, stop sending pushes."
    do {
        NSUInteger chunkCount = MIN(totalKeys - offset, maxKeysPerChunk);
        BOOL hasMore = (offset + chunkCount < totalKeys);
        
        NSMutableData *payload = [NSMutableData dataWithCapacity:3 + (chunkCount * SGP_ROUTING_KEY_LEN)];
        
        // 1. Flags (0x01 if more chunks are coming)
        uint8_t flags = hasMore ? 0x01 : 0x00;
        [payload appendBytes:&flags length:1];
        
        // 2. Count (Big Endian uint16)
        uint8_t countBE[2];
        countBE[0] = (chunkCount >> 8) & 0xFF;
        countBE[1] = chunkCount & 0xFF;
        [payload appendBytes:countBE length:2];
        
        // 3. Routing Keys
        for (NSUInteger i = 0; i < chunkCount; i++) {
            NSData *keyData = keys[offset + i];
            [payload appendData:keyData];
        }
        
        // Send chunk over TLS
        if (sendMsg(SGP_C_FILTER, [payload bytes], (uint32_t)[payload length]) != 0) {
            NSLog(@"[Protocol] Failed to send filter chunk at offset %lu", (unsigned long)offset);
            break; // Stop chunking if socket dies; it will retry on next connect
        }
        
        offset += chunkCount;
    } while (offset < totalKeys);
}

/* ─────────────────────────────────────────────────────────────────
 * handleMessage
 *
 * Called in a tight loop by the connection loop thread. Blocks until
 * one message arrives (or the Ping timeout fires), then dispatches it.
 *
 * select() timeout state machine:
 *   No pending Ping: wait SGP_PING_INTERVAL_SEC, then send C_PING.
 *   Pending Ping:    wait remaining Pong window; if elapsed, return TIMEOUT.
 *   Data arrives:    reset idle timer, read + dispatch one message.
 * ───────────────────────────────────────────────────────────────── */

int handleMessage(double pingIntervalSec) {
    if (!isConnected()) return SGP_ERR_IO;

    // ── select() with appropriate timeout ────────────────────────
    {
        long waitSec = (long)pingIntervalSec;

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
            if (_pingPendingSince > 0.0) {
                return SGP_OK;  // Pong window not yet elapsed
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
    // hdr[3] = header flags — reserved; ignore for forward compat.

    uint32_t payloadLen;
    memcpy(&payloadLen, hdr + 4, 4);
    payloadLen = ntohl(payloadLen);

    if (payloadLen > SGP_MAX_PAYLOAD_LEN) {
        NSLog(@"[Protocol] Payload too large: %u bytes", payloadLen);
        return SGP_ERR_PROTO;
    }

    // ── Read payload (NO MALLOC!) ──────────────────────────────────────────────
    // By reducing SGP_MAX_PAYLOAD_LEN to 4096, we can safely allocate this 
    // on the stack. This is infinitely faster and guarantees 0 memory leaks.
    uint8_t raw[SGP_MAX_PAYLOAD_LEN]; 
    
    if (payloadLen > 0) {
        if (sslReadExact(raw, (int)payloadLen) != 0) {
            NSLog(@"[Protocol] Failed to read %u-byte payload", payloadLen);
            return SGP_ERR_IO;
        }
    }
    const uint8_t *p = raw;

    // Any data from the server resets the client-initiated Ping timer.
    _pingPendingSince = 0.0;

    NSLog(@"[Protocol] ← type=0x%02X len=%u", (unsigned)msgType, payloadLen);

    int result = SGP_OK;

    switch (msgType) {

    /* ── SGP_S_HELLO ─────────────────────────────────────────────── */
    case SGP_S_HELLO: {
        uint32_t serverVer = 0;
        if (payloadLen >= 4) { memcpy(&serverVer, p, 4); serverVer = ntohl(serverVer); }
        NSLog(@"[Protocol] ← Hello: server version=%u", serverVer);
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

        // Route to the appropriate response based on whether we are registering
        // (C_REGISTER was sent) or logging in (C_LOGIN was sent).
        if (_regPendingAddress) {
            NSLog(@"[Protocol] Challenge (registration flow) — sending C_REGISTER_RESP");
            if (sendRegisterResponse() != 0) {
                NSLog(@"[Protocol] Failed to send register response");
                result = SGP_ERR_AUTH;
            }
        } else {
            NSLog(@"[Protocol] Challenge (login flow) — sending C_LOGIN_RESP");
            if (sendLoginResponse() != 0) {
                NSLog(@"[Protocol] Failed to send login response");
                result = SGP_ERR_AUTH;
            }
        }
        break;
    }

    /* ── SGP_S_AUTH_OK ───────────────────────────────────────────── */
    case SGP_S_AUTH_OK: {
        NSLog(@"[Protocol] ← AuthOK");
        if (_delegate) [_delegate authenticationSuccessful];
        sendMsg(SGP_C_POLL, NULL, 0);   // drain offline queue immediately
        break;
    }

    /* ── SGP_S_NOTIFY ────────────────────────────────────────────── */
    case SGP_S_NOTIFY: {
        // Minimum: routing_key[32]+msg_id[16]+device_seq[8]+expires_at[8]
        //         +flags[1]+payload_type[1]+data_len[4] = 70 bytes.
        if (payloadLen < SGP_NOTIFY_MIN_PAYLOAD) {
            NSLog(@"[Protocol] Notify: payload too short (%u, need %d)",
                  payloadLen, SGP_NOTIFY_MIN_PAYLOAD);
            result = SGP_ERR_PROTO; break;
        }
        if (!_delegate) { result = SGP_ERR_PROTO; break; }

        NSData *routingKey = [NSData dataWithBytes:p + SGP_NOTIFY_OFF_ROUTING_KEY
                                            length:SGP_ROUTING_KEY_LEN];
        NSData *msgID      = [NSData dataWithBytes:p + SGP_NOTIFY_OFF_MSG_ID
                                            length:SGP_MSG_ID_LEN];

        int64_t  deviceSeq = decodeBEInt64(p + SGP_NOTIFY_OFF_DEVICE_SEQ);
        int64_t  expiresAt = decodeBEInt64(p + SGP_NOTIFY_OFF_EXPIRES_AT);

        uint8_t  flags       = p[SGP_NOTIFY_OFF_FLAGS];
        uint8_t  payloadType = p[SGP_NOTIFY_OFF_PAYLOAD_TYPE];

        BOOL isEncrypted = (flags & SGP_NOTIFY_FLAG_ENCRYPTED) != 0;
        BOOL isCritical  = (flags & SGP_NOTIFY_FLAG_CRITICAL)  != 0;
        uint8_t priority = SGP_NOTIFY_GET_PRIORITY(flags);

        // REVISED: We now expect SGP_PAYLOAD_TYPE_BINARY (0x01) instead of JSON.
        // If the server sends anything else (like deprecated plists or future media types),
        // we reject it to avoid undefined parsing behavior.
        if (payloadType != SGP_PAYLOAD_TYPE_BINARY) {
            NSLog(@"[Protocol] Notify: unrecognised payload_type 0x%02X — rejecting", payloadType);
            // ACK with status=1 so the server stops re-queuing a message
            // this client version cannot handle.
            NSData *badMsgID = [NSData dataWithBytes:p + SGP_NOTIFY_OFF_MSG_ID length:SGP_MSG_ID_LEN];
            ackNotification(badMsgID, 1);
            break;  // SGP_OK — keep the connection alive
        }

        uint32_t dataLen;
        memcpy(&dataLen, p + SGP_NOTIFY_OFF_DATA_LEN, 4);
        dataLen = ntohl(dataLen);

        uint32_t cursor = SGP_NOTIFY_OFF_DATA;
        if ((uint64_t)cursor + dataLen > payloadLen) {
            NSLog(@"[Protocol] Notify: data_len %u overruns payload", dataLen);
            result = SGP_ERR_PROTO; break;
        }

        // Extract the exact data segment (plaintext TLV binary OR ciphertext)
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

        // Check expiry (expires_at = 0 means no expiry).
        if (expiresAt != 0 && expiresAt < (int64_t)time(NULL)) {
            NSLog(@"[Protocol] Notify: msg_id already expired (expires_at=%lld), discarding",
                  (long long)expiresAt);
            ackNotification(msgID, 0);
            break;
        }

        // Package the raw extracted data to be decrypted and TLV-parsed by the delegate
        NSMutableDictionary *notif = [NSMutableDictionary dictionaryWithObjectsAndKeys:
            routingKey,                 @"routing_key",
            msgID,                      @"msg_id",
            @(deviceSeq),               @"device_seq",
            @(expiresAt),               @"expires_at",
            @(isEncrypted),             @"is_encrypted",
            @(isCritical),              @"is_critical",
            @(priority),                @"priority",
            data,                       @"data",
            nil];
        if (iv) notif[@"iv"] = iv;

        [_delegate processNotificationMessage:notif];
        break;
    }

    /* ── SGP_S_DISCONNECT ────────────────────────────────────────── */
    case SGP_S_DISCONNECT: {
        // Payload: reason[1] + retry_after[4] = 5 bytes.
        // Old servers may send only 1 byte; tolerate gracefully.
        uint8_t reason = (payloadLen >= 1) ? p[0] : SGP_DISC_NORMAL;

        uint32_t retryAfter = 0;
        if (payloadLen >= 5) {
            memcpy(&retryAfter, p + 1, 4);
            retryAfter = ntohl(retryAfter);
        }
        _lastDisconnRetryAfter = retryAfter;

        NSLog(@"[Protocol] ← Disconnect reason=0x%02X (%s) retry_after=%u",
              reason,
              reason == SGP_DISC_AUTH_FAIL  ? "AUTH_FAIL"  :
              reason == SGP_DISC_PROTOCOL   ? "PROTOCOL"   :
              reason == SGP_DISC_SERVER_ERR ? "SERVER_ERR" :
              reason == SGP_DISC_REPLACED   ? "REPLACED"   : "NORMAL",
              retryAfter);

        if (reason == SGP_DISC_AUTH_FAIL) {
            result = SGP_ERR_AUTH;
        } else if (reason == SGP_DISC_REPLACED) {
            result = SGP_ERR_REPLACED;
        } else {
            result = SGP_ERR_CLOSED;
        }
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
        if (payloadLen == SGP_PING_SEQ_LEN) {
            uint64_t seq = 0;
            for (int i = 0; i < 8; i++) seq = (seq << 8) | p[i];
            NSLog(@"[Protocol] ← Pong seq=%llu (Ping Succeeded!)", (unsigned long long)seq);
            
            // Tell main.m the ping succeeded so it can grow the interval!
            if (_delegate && [_delegate respondsToSelector:@selector(keepAlivePingSucceeded)]) {
                [_delegate keepAlivePingSucceeded];
            }
        }
        break;
    }

    /* ── SGP_S_POLL_DONE ─────────────────────────────────────────── */
    case SGP_S_POLL_DONE: {
        // Server has flushed all offline notifications.
        // Notify the delegate (optional method) so the UI can dismiss
        // any "syncing…" indicator.
        NSLog(@"[Protocol] ← PollDone (offline queue drained)");
        if (_delegate && [_delegate respondsToSelector:@selector(offlineQueueDrainCompleted)]) {
            [_delegate offlineQueueDrainCompleted];
        }
        break;
    }

    /* ── SGP_S_PING ──────────────────────────────────────────────── */
    case SGP_S_PING: {
        // Server-initiated keepalive. MUST respond with C_PONG carrying
        // the same sequence bytes. Failure to pong causes server disconnect.
        uint8_t seq[SGP_PING_SEQ_LEN] = {0};
        if (payloadLen >= SGP_PING_SEQ_LEN) {
            memcpy(seq, p, SGP_PING_SEQ_LEN);
        }
        uint64_t seqVal = 0;
        for (int i = 0; i < 8; i++) seqVal = (seqVal << 8) | seq[i];
        NSLog(@"[Protocol] ← S_Ping seq=%llu — sending C_Pong", (unsigned long long)seqVal);
        if (sendMsg(SGP_C_PONG, seq, SGP_PING_SEQ_LEN) != 0) {
            NSLog(@"[Protocol] Failed to send C_Pong — treating as I/O error");
            result = SGP_ERR_IO;
        }
        break;
    }

    /* ── SGP_S_TIME_SYNC ─────────────────────────────────────────── */
    case SGP_S_TIME_SYNC: {
        // Sent by server immediately before S_DISCONNECT(AUTH_FAIL) when
        // it suspects clock skew. Parse server time, compare to local clock,
        // and log a clear warning if the skew exceeds the challenge window.
        // This helps diagnose an otherwise-opaque AUTH_FAIL.
        if (payloadLen >= 8) {
            int64_t serverTime = decodeBEInt64(p);
            int64_t localTime  = (int64_t)time(NULL);
            int64_t skew       = serverTime - localTime;

            if (llabs(skew) > SGP_CHALLENGE_WINDOW_SEC) {
                NSLog(@"[Protocol] ⚠️  CLOCK SKEW DETECTED: local=%lld server=%lld "
                      "delta=%+llds (limit ±%ds). "
                      "AUTH_FAIL is likely caused by device clock being wrong. "
                      "Correct the device time and try again.",
                      (long long)localTime, (long long)serverTime,
                      (long long)skew, SGP_CHALLENGE_WINDOW_SEC);
            } else {
                NSLog(@"[Protocol] ← TimeSync: server=%lld local=%lld delta=%+llds (within limit)",
                      (long long)serverTime, (long long)localTime, (long long)skew);
            }
        } else {
            NSLog(@"[Protocol] ← TimeSync: payload too short (%u)", payloadLen);
        }
        // Return SGP_OK — the AUTH_FAIL disconnect follows immediately.
        break;
    }

    /* ── SGP_S_REGISTER_OK ───────────────────────────────────────── */
    case SGP_S_REGISTER_OK: {
        // Payload: proto_ver[4]
        // The accepted device_address is the one we proposed in C_REGISTER —
        // the server does not assign a different one.
        uint32_t serverVer = 0;
        if (payloadLen >= 4) { memcpy(&serverVer, p, 4); serverVer = ntohl(serverVer); }

        // Retain before clearing the statics so the strings stay alive
        // across the delegate call and the plist write inside it.
        NSString *acceptedAddr = [_regPendingAddress retain];
        NSString *privKeyPEM   = [_regPendingPrivKey retain];

        NSLog(@"[Protocol] ← RegisterOK: addr=%@ serverVersion=%u",
              acceptedAddr, serverVer);

        // Clear pending RSA key — we no longer need it (private key is in privKeyPEM).
        if (_regPendingRSA) { RSA_free(_regPendingRSA); _regPendingRSA = NULL; }
        [_regPendingAddress release]; _regPendingAddress = nil;
        [_regPendingPrivKey release]; _regPendingPrivKey = nil;
        _regTimestamp      = 0;

        // Notify the delegate. The delegate is responsible for:
        //   1. Persisting device_address, privateKey, server_address to the profile plist.
        //   2. Calling startLogin() immediately on this same connection —
        //      the server has reset its state to CONNECTED and expects C_LOGIN next.
        if (_delegate && [_delegate respondsToSelector:
                @selector(registrationCompleted:privateKey:serverVersion:)]) {
            [_delegate registrationCompleted:acceptedAddr
                                  privateKey:privKeyPEM
                               serverVersion:serverVer];
        }
        [acceptedAddr release];
        [privKeyPEM release];
        break;
    }

    /* ── SGP_S_REGISTER_FAIL ─────────────────────────────────────── */
    case SGP_S_REGISTER_FAIL: {
        // Payload: reason_code[1] + reason_len[2] + reason[N]
        uint8_t reasonCode = (payloadLen >= 1) ? p[0] : 0xFF;
        NSString *reason = @"Unknown";
        if (payloadLen >= 3) {
            uint16_t reasonLen; memcpy(&reasonLen, p + 1, 2); reasonLen = ntohs(reasonLen);
            if ((uint32_t)3 + reasonLen <= payloadLen) {
                NSString *r = [[NSString alloc] initWithBytes:p + 3
                                                        length:reasonLen
                                                      encoding:NSUTF8StringEncoding];
                if (r) { reason = r; [r autorelease]; }
            }
        }

        NSLog(@"[Protocol] ← RegisterFail: code=0x%02X reason=%@", reasonCode, reason);

        // Clear pending registration state.
        if (_regPendingRSA) { RSA_free(_regPendingRSA); _regPendingRSA = NULL; }
        [_regPendingAddress release]; _regPendingAddress = nil;
        [_regPendingPrivKey release]; _regPendingPrivKey = nil;
        _regTimestamp      = 0;

        if (_delegate && [_delegate respondsToSelector:
                @selector(registrationFailed:reason:)]) {
            [_delegate registrationFailed:reasonCode reason:reason];
        }

        // Registration failure is unrecoverable on this connection.
        result = SGP_ERR_CLOSED;
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

    return result;
}