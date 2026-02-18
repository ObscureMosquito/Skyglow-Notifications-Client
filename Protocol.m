#import "Protocol.h"
#include <Foundation/NSObjCRuntime.h>
#include <Foundation/Foundation.h>
#include <objc/NSObjCRuntime.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>

// ──────────────────────────────────────────────
// Protocol message types (must match server)
// ──────────────────────────────────────────────

typedef enum {
    Hello                    = 0,
    LoginChallenge           = 1,
    RecieveNotification      = 2,
    AuthenticationSuccessful = 3,
    ServerDisconnect         = 4,
    // NOTE: DeviceTokenRegisterAck (5) removed — tokens are now local-only
} MessageTypesRecieved;

typedef enum {
    LoginRequest             = 0,
    LoginChallengeResponse   = 1,
    PollUnackedNotifications = 2,
    AckNotification          = 3,
    ClientDisconnect         = 4,
    // NOTE: RegisterDeviceToken (5) removed — tokens are now local-only
    SendFeedback             = 6,
} MessageTypesSent;

// ──────────────────────────────────────────────
// Tunables
// ──────────────────────────────────────────────

#define CONNECT_TIMEOUT_SEC     10   // TCP connect timeout
#define TLS_HANDSHAKE_TIMEOUT   15   // SSL_connect timeout (via SO_RCVTIMEO/SO_SNDTIMEO)
#define READ_TIMEOUT_SEC        0    // 0 = no read timeout (we want to block forever while idle)
#define MAX_MESSAGE_SIZE        (1024 * 1024)  // 1 MB sanity cap

// ──────────────────────────────────────────────
// Connection state (file-private)
// ──────────────────────────────────────────────

NSString *connectionStatus = @"Disconnected";

static id<NotificationDelegate> notificationDelegate = nil;

static SSL     *ssl    = NULL;
static SSL_CTX *sslctx = NULL;
static int      sock   = -1;

/// Guards ssl, sslctx, sock to prevent concurrent access from
/// the message loop thread and external disconnect calls.
static NSObject *connectionLock = nil;

static NSString *user_address = nil;
static RSA      *user_privKey = NULL;

/// Ensure the connection lock is initialized exactly once.
static void ensureConnectionLock(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        connectionLock = [[NSObject alloc] init];
    });
}

// ──────────────────────────────────────────────
// OpenSSL error helpers
// ──────────────────────────────────────────────

static void logOpenSSLErrors(NSString *context) {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        NSLog(@"[Protocol] %@: %s", context, buf);
    }
}

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

void setNotificationDelegate(id<NotificationDelegate> delegate) {
    notificationDelegate = delegate;
}

BOOL isConnected(void) {
    return (ssl != NULL && sock >= 0);
}

static int sslReadExact(void *buf, int len) {
    if (!ssl) return -1;
    int total = 0;
    while (total < len) {
        int n = SSL_read(ssl, (char *)buf + total, len - total);
        if (n <= 0) {
            int sslErr = SSL_get_error(ssl, n);
            if (sslErr == SSL_ERROR_WANT_READ || sslErr == SSL_ERROR_WANT_WRITE) {
                continue;
            }
            NSLog(@"[Protocol] SSL_read failed: ssl_error=%d errno=%d (%s)",
                  sslErr, errno, strerror(errno));
            logOpenSSLErrors(@"SSL_read");
            return -1;
        }
        total += n;
    }
    return 0;
}

static int sslWriteExact(const void *buf, int len) {
    if (!ssl) return -1;
    int total = 0;
    while (total < len) {
        int n = SSL_write(ssl, (const char *)buf + total, len - total);
        if (n <= 0) {
            int sslErr = SSL_get_error(ssl, n);
            if (sslErr == SSL_ERROR_WANT_WRITE || sslErr == SSL_ERROR_WANT_READ) {
                continue;
            }
            NSLog(@"[Protocol] SSL_write failed: ssl_error=%d errno=%d (%s)",
                  sslErr, errno, strerror(errno));
            logOpenSSLErrors(@"SSL_write");
            return -1;
        }
        total += n;
    }
    return 0;
}

// ──────────────────────────────────────────────
// Non-blocking connect with timeout
// ──────────────────────────────────────────────

/// Connect a socket with a timeout (in seconds).
/// Returns 0 on success, -1 on failure/timeout.
static int connectWithTimeout(int sockfd, struct sockaddr *addr, socklen_t addrLen, int timeoutSec) {
    // Save original flags
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) return -1;

    // Set non-blocking
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;

    int result = connect(sockfd, addr, addrLen);

    if (result == 0) {
        // Connected immediately (unlikely but possible on localhost)
        fcntl(sockfd, F_SETFL, flags); // restore blocking
        return 0;
    }

    if (errno != EINPROGRESS) {
        NSLog(@"[Protocol] connect() failed immediately: %s (errno=%d)", strerror(errno), errno);
        fcntl(sockfd, F_SETFL, flags);
        return -1;
    }

    // Wait for the connection to complete or timeout
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sockfd, &writefds);

    struct timeval tv;
    tv.tv_sec  = timeoutSec;
    tv.tv_usec = 0;

    result = select(sockfd + 1, NULL, &writefds, NULL, &tv);

    // Restore blocking mode BEFORE checking result
    fcntl(sockfd, F_SETFL, flags);

    if (result <= 0) {
        if (result == 0) {
            NSLog(@"[Protocol] connect() timed out after %d seconds", timeoutSec);
            errno = ETIMEDOUT;
        } else {
            NSLog(@"[Protocol] select() error: %s (errno=%d)", strerror(errno), errno);
        }
        return -1;
    }

    // Check if connect actually succeeded
    int connectError = 0;
    socklen_t errLen = sizeof(connectError);
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &connectError, &errLen) < 0) {
        NSLog(@"[Protocol] getsockopt(SO_ERROR) failed: %s", strerror(errno));
        return -1;
    }

    if (connectError != 0) {
        NSLog(@"[Protocol] connect() failed: %s (errno=%d)", strerror(connectError), connectError);
        errno = connectError;
        return -1;
    }

    return 0; // success
}

// ──────────────────────────────────────────────
// Send / receive helpers
// ──────────────────────────────────────────────

static BOOL sendMessage(MessageTypesSent messageType, NSMutableDictionary *dataToSend) {
    if (!isConnected()) {
        NSLog(@"[Protocol] sendMessage: not connected");
        return NO;
    }

    dataToSend[@"$type"] = @(messageType);

    NSError *error = nil;
    NSData *plistData = [NSPropertyListSerialization dataWithPropertyList:dataToSend
                                                                  format:NSPropertyListBinaryFormat_v1_0
                                                                 options:0
                                                                   error:&error];
    if (!plistData) {
        NSLog(@"[Protocol] Plist serialization error: %@", error);
        return NO;
    }

    uint32_t length = htonl((uint32_t)[plistData length]);
    if (sslWriteExact(&length, 4) != 0)  return NO;
    if (sslWriteExact([plistData bytes], (int)[plistData length]) != 0) return NO;
    return YES;
}

static void checkOfflineNotifications(void) {
    sendMessage(PollUnackedNotifications, [NSMutableDictionary dictionary]);
}

// ──────────────────────────────────────────────
// Public: outbound messages
// ──────────────────────────────────────────────

void ackNotification(NSString *notificationUUID, int status) {
    if (!notificationUUID) return;
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                 notificationUUID, @"notification",
                                 @(status), @"status",
                                 nil];
    sendMessage(AckNotification, dict);
}

void sendFeedback(NSData *routing_token, NSNumber *type, NSString *reason) {
    if (!routing_token) return;
    if (!isConnected()) {
        NSLog(@"[Protocol] sendFeedback: not connected, feedback will be lost");
        return;
    }
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                 routing_token, @"routing_token",
                                 type  ?: @0,   @"type",
                                 reason ?: @"", @"reason",
                                 nil];
    sendMessage(SendFeedback, dict);
}

void sendClientDisconnect(void) {
    if (!isConnected()) return;
    NSLog(@"[Protocol] Sending ClientDisconnect to server");
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    sendMessage(ClientDisconnect, dict);
}

// ──────────────────────────────────────────────
// Connection lifecycle (thread-safe)
// ──────────────────────────────────────────────

void disconnectFromServer(void) {
    ensureConnectionLock();
    @synchronized(connectionLock) {
        // Close socket first — this unblocks any SSL_read/SSL_write
        // that may be blocked on the message loop thread.
        int sockCopy = sock;
        sock = -1;
        if (sockCopy >= 0) {
            // Shut down the socket to unblock SSL_read
            shutdown(sockCopy, SHUT_RDWR);
            close(sockCopy);
        }

        if (ssl) {
            // Don't call SSL_shutdown — the socket is already closed.
            // SSL_shutdown would try to send a close_notify which would fail.
            SSL_free(ssl);
            ssl = NULL;
        }
        if (sslctx) {
            SSL_CTX_free(sslctx);
            sslctx = NULL;
        }
        connectionStatus = @"Disconnected";
    }
}

int connectToServer(const char *serverIP, int port, NSString *serverCert) {
    ensureConnectionLock();
    signal(SIGPIPE, SIG_IGN);
    disconnectFromServer();
    ERR_clear_error();

    // NOTE: SSL_library_init() / SSL_load_error_strings() / OpenSSL_add_all_algorithms()
    // are called once in main(). They are idempotent but wasteful to repeat.

    const SSL_METHOD *method = SSLv23_client_method();

    SSL_CTX *newCtx = SSL_CTX_new(method);
    if (!newCtx) {
        NSLog(@"[Protocol] Failed to create SSL_CTX");
        logOpenSSLErrors(@"SSL_CTX_new");
        return -1;
    }

    SSL_CTX_set_options(newCtx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_verify(newCtx, SSL_VERIFY_PEER, NULL);

    if (!serverCert || [serverCert length] == 0) {
        NSLog(@"[Protocol] No server certificate provided");
        SSL_CTX_free(newCtx);
        return -2;
    }

    BIO *bio = BIO_new_mem_buf((void *)[serverCert UTF8String], -1);
    if (!bio) {
        NSLog(@"[Protocol] Failed to create BIO");
        logOpenSSLErrors(@"BIO_new");
        SSL_CTX_free(newCtx);
        return -2;
    }

    X509 *cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
    BIO_free(bio);
    if (!cert) {
        NSLog(@"[Protocol] Failed to parse server certificate PEM");
        logOpenSSLErrors(@"PEM_read_bio_X509");
        SSL_CTX_free(newCtx);
        return -2;
    }

    char certSubject[256];
    X509_NAME_oneline(X509_get_subject_name(cert), certSubject, sizeof(certSubject));
    NSLog(@"[Protocol] Pinned cert: %s", certSubject);

    X509_STORE *store = SSL_CTX_get_cert_store(newCtx);
    int addResult = X509_STORE_add_cert(store, cert);
    X509_free(cert);
    if (addResult != 1) {
        NSLog(@"[Protocol] Failed to add certificate to trust store");
        logOpenSSLErrors(@"X509_STORE_add_cert");
        SSL_CTX_free(newCtx);
        return -2;
    }

    // ── TCP socket ──
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        NSLog(@"[Protocol] socket() failed: %s", strerror(errno));
        SSL_CTX_free(newCtx);
        return -3;
    }

    // Enable TCP keepalive — detects dead connections faster
    int keepAlive = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &keepAlive, sizeof(keepAlive));

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port   = htons(port);

    if (inet_pton(AF_INET, serverIP, &serverAddr.sin_addr) <= 0) {
        NSLog(@"[Protocol] inet_pton failed for '%s'", serverIP);
        close(sockfd);
        SSL_CTX_free(newCtx);
        return -4;
    }

    NSLog(@"[Protocol] Connecting to %s:%d (timeout %ds)...", serverIP, port, CONNECT_TIMEOUT_SEC);

    // ── Non-blocking connect with timeout ──
    if (connectWithTimeout(sockfd, (struct sockaddr *)&serverAddr,
                           sizeof(serverAddr), CONNECT_TIMEOUT_SEC) != 0) {
        NSLog(@"[Protocol] TCP connect failed: %s (errno=%d)", strerror(errno), errno);
        close(sockfd);
        SSL_CTX_free(newCtx);
        return -5;
    }

    NSLog(@"[Protocol] TCP connected, starting TLS handshake...");

    // Set TLS handshake timeouts (these apply to SSL_connect's read/write calls)
    struct timeval tv;
    tv.tv_sec = TLS_HANDSHAKE_TIMEOUT; tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    SSL *newSsl = SSL_new(newCtx);
    if (!newSsl) {
        NSLog(@"[Protocol] SSL_new failed");
        logOpenSSLErrors(@"SSL_new");
        close(sockfd);
        SSL_CTX_free(newCtx);
        return -6;
    }

    SSL_set_fd(newSsl, sockfd);

    int sslResult = SSL_connect(newSsl);
    if (sslResult != 1) {
        int sslError = SSL_get_error(newSsl, sslResult);
        NSLog(@"[Protocol] SSL_connect FAILED: return=%d ssl_error=%d errno=%d (%s)",
              sslResult, sslError, errno, strerror(errno));
        logOpenSSLErrors(@"SSL_connect");

        long verifyResult = SSL_get_verify_result(newSsl);
        if (verifyResult != X509_V_OK) {
            NSLog(@"[Protocol] Cert verify error %ld: %s",
                  verifyResult, X509_verify_cert_error_string(verifyResult));
        }

        X509 *peerCert = SSL_get_peer_certificate(newSsl);
        if (peerCert) {
            char peerSubject[256];
            X509_NAME_oneline(X509_get_subject_name(peerCert), peerSubject, sizeof(peerSubject));
            NSLog(@"[Protocol] Server cert: %s", peerSubject);
            X509_free(peerCert);
        } else {
            NSLog(@"[Protocol] Server presented NO certificate — "
                  @"likely not a TLS endpoint! Check tcp_port in DNS TXT.");
        }

        SSL_free(newSsl);
        close(sockfd);
        SSL_CTX_free(newCtx);
        return -7;
    }

    // ── Success — commit to global state under lock ──
    NSLog(@"[Protocol] TLS OK: %s, cipher: %s", SSL_get_version(newSsl), SSL_get_cipher(newSsl));

    // Clear the handshake timeouts — the message loop should block indefinitely
    // waiting for server pushes (the daemon sleeps here when idle)
    tv.tv_sec = 0; tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    @synchronized(connectionLock) {
        sslctx = newCtx;
        ssl    = newSsl;
        sock   = sockfd;
    }

    connectionStatus = @"ConnectedNotAuthenticated";
    NSLog(@"[Protocol] Connected to %s:%d", serverIP, port);
    return 0;
}

// ──────────────────────────────────────────────
// Message handling
// ──────────────────────────────────────────────

int handleMessage(void) {
    if (!isConnected()) {
        NSLog(@"[Protocol] handleMessage: not connected");
        return 3;
    }

    uint32_t netLength = 0;
    if (sslReadExact(&netLength, 4) != 0) {
        NSLog(@"[Protocol] Failed to read message length");
        return 3;
    }

    uint32_t length = ntohl(netLength);
    if (length == 0 || length > MAX_MESSAGE_SIZE) {
        NSLog(@"[Protocol] Invalid message length: %u", length);
        return 2;
    }

    NSMutableData *receivedDataRaw = [NSMutableData dataWithLength:length];
    if (sslReadExact([receivedDataRaw mutableBytes], (int)length) != 0) {
        NSLog(@"[Protocol] Failed to read payload (%u bytes)", length);
        return 3;
    }

    NSError *error = nil;
    NSDictionary *receivedData = [NSPropertyListSerialization propertyListWithData:receivedDataRaw
                                                                           options:NSPropertyListImmutable
                                                                            format:nil
                                                                             error:&error];
    if (!receivedData || ![receivedData isKindOfClass:[NSDictionary class]]) {
        NSLog(@"[Protocol] Deserialization error: %@", error);
        return 2;
    }

    NSNumber *typeNum = receivedData[@"$type"];
    if (!typeNum) {
        NSLog(@"[Protocol] Message missing $type");
        return 2;
    }
    MessageTypesRecieved messageType = (MessageTypesRecieved)[typeNum unsignedIntegerValue];
    NSLog(@"[Protocol] Received message type %u", (unsigned)messageType);

    switch (messageType) {

    case Hello:
        if (!notificationDelegate) {
            NSLog(@"[Protocol] Hello but no delegate");
            return 2;
        }
        [notificationDelegate handleWelcomeMessage];
        return 0;

    case LoginChallenge: {
        NSData *challengeEncrypted = receivedData[@"challenge"];
        if (!challengeEncrypted || ![challengeEncrypted isKindOfClass:[NSData class]]) {
            NSLog(@"[Protocol] Missing or invalid challenge data");
            return 2;
        }
        if (!user_privKey) {
            NSLog(@"[Protocol] No private key for challenge");
            return 4;
        }

        const size_t rsaSize = RSA_size(user_privKey);
        unsigned char *decBuf = malloc(rsaSize);
        if (!decBuf) return 2;

        int decLen = RSA_private_decrypt(
            (int)[challengeEncrypted length],
            [challengeEncrypted bytes],
            decBuf, user_privKey, RSA_PKCS1_OAEP_PADDING);

        if (decLen <= 0) {
            free(decBuf);
            logOpenSSLErrors(@"RSA_private_decrypt");
            return 4;
        }

        NSData *decData = [NSData dataWithBytesNoCopy:decBuf length:decLen freeWhenDone:YES];
        NSString *decStr = [[NSString alloc] initWithData:decData encoding:NSUTF8StringEncoding];
        if (!decStr) {
            NSLog(@"[Protocol] Challenge not valid UTF-8");
            return 4;
        }

        NSArray *parts = [decStr componentsSeparatedByString:@","];
        if ([parts count] < 3) {
            NSLog(@"[Protocol] Malformed challenge (%lu parts)", (unsigned long)[parts count]);
            return 4;
        }

        if (![parts[0] isEqualToString:user_address]) {
            NSLog(@"[Protocol] Challenge address mismatch: '%@' vs '%@'", parts[0], user_address);
            return 4;
        }

        NSTimeInterval ts = [parts[2] doubleValue];
        NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
        if (ts < now - 300.0 || ts > now + 60.0) {
            NSLog(@"[Protocol] Challenge timestamp out of range: %@", parts[2]);
            return 4;
        }

        NSMutableDictionary *resp = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                     parts[1], @"nonce",
                                     parts[2], @"timestamp",
                                     nil];
        if (!sendMessage(LoginChallengeResponse, resp)) return 3;
        return 0;
    }

    case AuthenticationSuccessful:
        connectionStatus = @"Connected";
        NSLog(@"[Protocol] Authenticated");
        if (notificationDelegate) [notificationDelegate authenticationSuccessful];
        checkOfflineNotifications();
        return 0;

    case RecieveNotification:
        if (!notificationDelegate) {
            NSLog(@"[Protocol] Notification but no delegate");
            return 2;
        }
        [notificationDelegate processNotificationMessage:receivedData];
        return 0;

    case ServerDisconnect:
        NSLog(@"[Protocol] Server disconnect");
        connectionStatus = @"Disconnected";
        return 1;

    default:
        NSLog(@"[Protocol] Unknown message type: %u", (unsigned)messageType);
        return 0;
    }
}

void startLogin(NSString *address, RSA *auth_privKey, NSString *language) {
    user_address = address;
    user_privKey = auth_privKey;
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                 address,           @"address",
                                 protocolVersion,   @"version",
                                 language ?: @"en", @"lang",
                                 nil];
    sendMessage(LoginRequest, dict);
}