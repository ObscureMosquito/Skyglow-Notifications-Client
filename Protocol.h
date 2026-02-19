#ifndef SKYGLOW_PROTOCOL_H
#define SKYGLOW_PROTOCOL_H

/*
 * Protocol.h — Skyglow Notification Daemon
 * Skyglow Protocol version 2 (SGP/2)
 *
 * ═══════════════════════════════════════════════════════════════════════
 * MOTIVATION
 * ═══════════════════════════════════════════════════════════════════════
 *
 * SGP/1 used binary-plist framing: [4-byte length][binary plist body].
 * This caused several reliability and security problems:
 *
 *   • Parsing overhead: every message required a full plist deserialise
 *     (heap alloc, ObjC object graph, autorelease drain).
 *   • Apple dependency on server: the Go server needed howett.net/plist.
 *   • Auth fragility: the challenge was "addr,nonce,ts" RSA-OAEP-encrypted,
 *     then the decrypted components were returned as plaintext UTF-8.
 *     Fragile CSV parsing, and RSA-decrypt is the wrong primitive for
 *     authentication (signing is).
 *   • No keepalive: READ_TIMEOUT_SEC=0 meant a silently-dropped NAT
 *     mapping left the daemon blocked in SSL_read forever, stuck in
 *     SGStateConnected.
 *   • Write races: registerDeviceToken() was called from the MachMsgs
 *     thread without any mutex on the shared SSL session.
 *
 * SGP/2 fixes all of these with a compact 8-byte binary header,
 * RSA-PSS-SHA256 authentication, application-level Ping/Pong, and a
 * per-send mutex.
 *
 * ═══════════════════════════════════════════════════════════════════════
 * WIRE FORMAT
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Every message in both directions uses an 8-byte fixed header:
 *
 *   Offset  Size  Field
 *   ──────  ────  ─────────────────────────────────────────────────
 *   0       1     magic       SGP_MAGIC (0x53 = 'S').
 *                             Wrong magic → close immediately.
 *   1       1     version     SGP_VERSION (0x02).
 *                             Unsupported version → close immediately.
 *   2       1     type        SGPMsgType enum value.
 *   3       1     flags       Reserved. Send as 0x00.
 *                             Receivers SHOULD ignore unknown bits
 *                             to allow non-breaking future extensions.
 *   4       4     payload_len Big-endian uint32. Bytes that follow.
 *                             0 is valid (empty payload).
 *                             Must be ≤ SGP_MAX_PAYLOAD_LEN.
 *   8+      N     payload     Layout defined per type below.
 *
 * The header and payload are written in a single locked SSL_write call
 * so they can never be interleaved with a concurrent sender.
 *
 * ═══════════════════════════════════════════════════════════════════════
 * AUTHENTICATION FLOW
 * ═══════════════════════════════════════════════════════════════════════
 *
 *   Client                               Server
 *   ──────                               ──────
 *   TCP + TLS connect ──────────────────>
 *                     <──────────────── Hello  (server_version[4])
 *   LoginRequest ──────────────────────> (addr_len[2]+addr+timestamp[8]+proto_ver[4])
 *                     <──────────────── LoginChallenge  (nonce[32])
 *   LoginResponse ─────────────────────> (timestamp[8]+sig_len[2]+sig[N])
 *                     <──────────────── AuthOK  — or —  Disconnect(AuthFail)
 *   PollUnacked ───────────────────────> (empty — drain offline queue)
 *   … steady state …
 *   Ping ──────────────────────────────> (seq[8])
 *                     <──────────────── Pong  (seq[8] echo)
 *
 * CHALLENGE-RESPONSE DETAIL:
 *
 *   Server sends 32 random bytes (nonce) in SGP_S_CHALLENGE.
 *
 *   Client computes an RSA-PSS-SHA256 signature over:
 *       signed_data = nonce[32] || device_address_utf8 || login_timestamp_be[8]
 *   where login_timestamp_be is the same 8 bytes sent in SGP_C_LOGIN.
 *
 *   Server verifies with the stored client public key.
 *   Timestamp must be within ±SGP_CHALLENGE_WINDOW_SEC of server time.
 *
 *   Why PSS instead of SGP/1's RSA-OAEP decrypt?
 *   • Signing is the correct primitive for proving key possession.
 *     Decryption is not — it proves you can decrypt, not that you own
 *     the key. The server only needs to verify, never to decrypt.
 *   • No plaintext challenge material travels on the wire.
 *   • PSS with random salt is probabilistic: each signature is unique
 *     even for identical inputs, preventing signature replay attacks.
 *   • TLS 1.2+ already prevents channel-level replay; PSS closes the
 *     remaining cryptographic gap.
 *
 * ═══════════════════════════════════════════════════════════════════════
 * PING / PONG (dead-connection detection)
 * ═══════════════════════════════════════════════════════════════════════
 *
 *   After SGP_PING_INTERVAL_SEC seconds without receiving any data from
 *   the server, handleMessage() sends SGP_C_PING with a monotonically
 *   increasing 8-byte sequence counter (big-endian uint64).
 *
 *   The server echoes the sequence bytes in SGP_S_PONG.
 *
 *   Any incoming data (Pong or otherwise) resets the idle timer.
 *   If no data arrives within SGP_PONG_TIMEOUT_SEC of the Ping being
 *   sent, handleMessage() returns SGP_ERR_TIMEOUT and the daemon
 *   transitions to SGStateBackingOff and reconnects.
 *
 *   Why not rely on SO_KEEPALIVE alone?
 *   TCP keepalive operates below TLS. A middlebox can silently drop
 *   packets after the TLS handshake while the kernel still considers
 *   the socket alive. Application-level Ping/Pong guarantees end-to-end
 *   liveness at the TLS session layer. Both mechanisms are enabled:
 *     • TCP keepalive: catches kernel-level connection staleness.
 *     • SGP Ping/Pong: catches TLS-layer and middlebox-level staleness.
 *
 * ═══════════════════════════════════════════════════════════════════════
 * MESSAGE TYPE CATALOGUE
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Server → Client  (0x10–0x1F)
 * ─────────────────────────────────────────────────────────────────────
 *
 * SGP_S_HELLO (0x10)
 *   First message from server after TLS handshake completes.
 *   Client MUST NOT send anything before receiving this.
 *   Payload: server_version[4]  (big-endian uint32, informational)
 *
 * SGP_S_CHALLENGE (0x11)
 *   Sent in response to SGP_C_LOGIN. Client must sign and respond.
 *   Payload: nonce[32]  (cryptographically random, single-use)
 *
 * SGP_S_AUTH_OK (0x12)
 *   Authentication accepted. Client sends SGP_C_POLL immediately after.
 *   Payload: empty.
 *
 * SGP_S_NOTIFY (0x13)
 *   Incoming notification. Minimum payload = 53 bytes.
 *   Payload layout:
 *     routing_key[32]    Matches a routing key registered via SGP_C_REG_TOKEN.
 *     msg_id[16]         128-bit message ID, raw bytes (not UUID text).
 *     flags[1]           bit 0: is_encrypted  (1 = AES-256-GCM, 0 = plaintext)
 *                        bit 1: is_json       (1 = JSON, 0 = binary plist)
 *                        bits 2–7: reserved, must be 0.
 *     data_len[4]        big-endian uint32.
 *     data[data_len]     Plaintext payload, OR ciphertext with the 16-byte
 *                        GCM auth tag appended as the last 16 bytes.
 *   If is_encrypted == 1, immediately after data[]:
 *     iv[12]             AES-GCM nonce. Fixed 12 bytes, no length prefix.
 *
 * SGP_S_DISCONNECT (0x14)
 *   Server is closing the connection. Connection is done after this.
 *   Payload: reason[1]  (SGPDisconnReason code)
 *
 * SGP_S_TOKEN_ACK (0x15)
 *   Token registration confirmed by server.
 *   Payload:
 *     routing_key[32]
 *     bundle_id_len[2]   big-endian uint16
 *     bundle_id[N]       UTF-8, no NUL terminator
 *
 * SGP_S_PONG (0x16)
 *   Echo of the client's last Ping sequence bytes.
 *   Payload: seq[8]  (verbatim copy of the SGP_C_PING payload)
 *
 * Client → Server  (0x20–0x2F)
 * ─────────────────────────────────────────────────────────────────────
 *
 * SGP_C_LOGIN (0x20)
 *   Begin authentication. Sent upon receiving SGP_S_HELLO.
 *   Payload:
 *     addr_len[2]        big-endian uint16
 *     addr[N]            UTF-8 device address
 *     timestamp[8]       big-endian int64, Unix seconds. Must be echoed
 *                        verbatim in SGP_C_LOGIN_RESP.
 *     proto_version[4]   big-endian uint32, must equal SGP_VERSION.
 *
 * SGP_C_LOGIN_RESP (0x21)
 *   Challenge response. Sent after receiving SGP_S_CHALLENGE.
 *   Payload:
 *     timestamp[8]       big-endian int64. Same value as SGP_C_LOGIN.
 *     sig_len[2]         big-endian uint16.
 *     sig[sig_len]       RSA-PSS-SHA256 over (nonce[32]||addr_utf8||timestamp_be[8]).
 *
 * SGP_C_POLL (0x22)
 *   Drain offline notification queue. Send immediately after AuthOK.
 *   Payload: empty.
 *
 * SGP_C_ACK (0x23)
 *   Acknowledge a notification after delivering it to the OS.
 *   Payload:
 *     msg_id[16]         Verbatim from SGP_S_NOTIFY.
 *     status[1]          0 = delivered OK
 *                        1 = decryption failed
 *                        2 = parse/deserialisation failed
 *
 * SGP_C_DISCONNECT (0x24)
 *   Clean shutdown signal. Send before closing TLS.
 *   Payload: reason[1]  (SGPDisconnReason, normally SGP_DISC_NORMAL)
 *
 * SGP_C_REG_TOKEN (0x25)
 *   Register a device token for routing.
 *   Payload:
 *     routing_key[32]    SHA-256 of the per-app secret K.
 *     bundle_id_len[2]   big-endian uint16
 *     bundle_id[N]       UTF-8, no NUL
 *
 * SGP_C_FEEDBACK (0x26)
 *   Report a token as invalid (app uninstalled, etc.).
 *   Payload:
 *     routing_key[32]
 *     type[1]            Feedback type code.
 *     reason_len[2]      big-endian uint16
 *     reason[N]          UTF-8 human-readable reason
 *
 * SGP_C_PING (0x27)
 *   Keepalive probe. Sent when idle for SGP_PING_INTERVAL_SEC seconds.
 *   Payload: seq[8]  (monotonically increasing big-endian uint64)
 *
 * ═══════════════════════════════════════════════════════════════════════
 * DISCONNECT REASON CODES
 * ═══════════════════════════════════════════════════════════════════════
 *
 *   SGP_DISC_NORMAL     0x00  Clean voluntary close.
 *   SGP_DISC_AUTH_FAIL  0x01  Challenge response was wrong.
 *   SGP_DISC_PROTOCOL   0x02  Malformed or unexpected message.
 *   SGP_DISC_SERVER_ERR 0x03  Server-side error; retry later.
 *   SGP_DISC_REPLACED   0x04  A newer connection replaced this one.
 *
 * ═══════════════════════════════════════════════════════════════════════
 * handleMessage() RETURN CODES
 * ═══════════════════════════════════════════════════════════════════════
 *
 *   SGP_OK           0   Message handled; keep calling.
 *   SGP_ERR_CLOSED   1   Server sent Disconnect; stop the loop.
 *   SGP_ERR_PROTO    2   Protocol violation; close and reconnect.
 *   SGP_ERR_IO       3   I/O failure; close and reconnect.
 *   SGP_ERR_AUTH     4   Auth failure; back off before retrying.
 *   SGP_ERR_TIMEOUT  5   Pong not received; close and reconnect.
 *
 * ═══════════════════════════════════════════════════════════════════════
 * NOTIFICATION DELEGATE DICTIONARY KEYS  (processNotificationMessage:)
 * ═══════════════════════════════════════════════════════════════════════
 *
 *   @"routing_key"   NSData (SGP_ROUTING_KEY_LEN bytes).  DB lookup key.
 *   @"msg_id"        NSData (SGP_MSG_ID_LEN bytes).        Pass to ackNotification:.
 *   @"is_encrypted"  NSNumber (BOOL).
 *   @"data_type"     NSString.  @"json" or @"plist".
 *   @"data"          NSData.    Encrypted: ciphertext with GCM tag as last 16 bytes.
 *                               Plaintext: raw notification bytes.
 *   @"iv"            NSData (SGP_GCM_IV_LEN bytes).  Only present when is_encrypted=YES.
 */

#include <Foundation/Foundation.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <SystemConfiguration/SCNetworkReachability.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>

/* ─────────────────────────────────────────────────────────────────
 * Wire constants
 * ───────────────────────────────────────────────────────────────── */

#define SGP_MAGIC               ((uint8_t)0x53)   ///< 'S' — first byte of every message
#define SGP_VERSION             ((uint8_t)0x02)   ///< Protocol version in every header
#define SGP_HEADER_SIZE         8                 ///< Fixed header length in bytes
#define SGP_MAX_PAYLOAD_LEN     (256u * 1024u)    ///< Hard cap on payload size: 256 KB

/* ─────────────────────────────────────────────────────────────────
 * Timing (seconds)
 * ───────────────────────────────────────────────────────────────── */

#define SGP_PING_INTERVAL_SEC      60   ///< Idle time before client sends a Ping
#define SGP_PONG_TIMEOUT_SEC       15   ///< Time to wait for Pong before declaring dead
#define SGP_CHALLENGE_WINDOW_SEC  300   ///< Max acceptable clock skew for auth timestamp

/* ─────────────────────────────────────────────────────────────────
 * Fixed field lengths (bytes)
 * ───────────────────────────────────────────────────────────────── */

#define SGP_ROUTING_KEY_LEN     32   ///< SHA-256 of per-app secret K
#define SGP_MSG_ID_LEN          16   ///< 128-bit message ID, raw bytes
#define SGP_NONCE_LEN           32   ///< Server challenge nonce
#define SGP_PING_SEQ_LEN         8   ///< Ping/Pong sequence counter
#define SGP_GCM_IV_LEN          12   ///< AES-GCM nonce (always 12 bytes)
#define SGP_GCM_TAG_LEN         16   ///< AES-GCM auth tag, appended to ciphertext

/* ─────────────────────────────────────────────────────────────────
 * Message types
 * ───────────────────────────────────────────────────────────────── */

typedef enum : uint8_t {
    /* Server → Client */
    SGP_S_HELLO         = 0x10,
    SGP_S_CHALLENGE     = 0x11,
    SGP_S_AUTH_OK       = 0x12,
    SGP_S_NOTIFY        = 0x13,
    SGP_S_DISCONNECT    = 0x14,
    SGP_S_TOKEN_ACK     = 0x15,
    SGP_S_PONG          = 0x16,

    /* Client → Server */
    SGP_C_LOGIN         = 0x20,
    SGP_C_LOGIN_RESP    = 0x21,
    SGP_C_POLL          = 0x22,
    SGP_C_ACK           = 0x23,
    SGP_C_DISCONNECT    = 0x24,
    SGP_C_REG_TOKEN     = 0x25,
    SGP_C_FEEDBACK      = 0x26,
    SGP_C_PING          = 0x27,
} SGPMsgType;

/* ─────────────────────────────────────────────────────────────────
 * Disconnect reason codes
 * ───────────────────────────────────────────────────────────────── */

typedef enum : uint8_t {
    SGP_DISC_NORMAL     = 0x00,
    SGP_DISC_AUTH_FAIL  = 0x01,
    SGP_DISC_PROTOCOL   = 0x02,
    SGP_DISC_SERVER_ERR = 0x03,
    SGP_DISC_REPLACED   = 0x04,
} SGPDisconnReason;

/* ─────────────────────────────────────────────────────────────────
 * handleMessage() return codes
 * ───────────────────────────────────────────────────────────────── */

#define SGP_OK          0   ///< Handled OK; keep calling
#define SGP_ERR_CLOSED  1   ///< Server sent Disconnect; stop loop
#define SGP_ERR_PROTO   2   ///< Protocol violation; close + reconnect
#define SGP_ERR_IO      3   ///< I/O error; close + reconnect
#define SGP_ERR_AUTH    4   ///< Auth failure; back off
#define SGP_ERR_TIMEOUT 5   ///< Pong timeout; close + reconnect

/* ─────────────────────────────────────────────────────────────────
 * Notification delegate
 * ───────────────────────────────────────────────────────────────── */

@protocol NotificationDelegate <NSObject>
/// Incoming notification. Dictionary keys documented above.
- (void)processNotificationMessage:(NSDictionary *)notificationData;
/// Server sent Hello — trigger startLogin.
- (void)handleWelcomeMessage;
/// Server sent AuthOK.
- (void)authenticationSuccessful;
/// Server confirmed token registration.
- (void)deviceTokenRegistrationCompleted:(NSString *)bundleId;
@end

/* ─────────────────────────────────────────────────────────────────
 * Public API
 * ───────────────────────────────────────────────────────────────── */

/// Set the delegate. Call before connectToServer.
void setNotificationDelegate(id<NotificationDelegate> delegate);

/// Establish TLS to serverIP:port, pinning the PEM certificate string.
/// OpenSSL must already be initialised (main.m calls initOpenSSLOnce).
/// Returns 0 on success, negative on failure.
int connectToServer(const char *serverIP, int port, NSString *serverCert);

/// Tear down TLS and release all SSL state. Safe when not connected.
void disconnectFromServer(void);

/// Send SGP_C_DISCONNECT(Normal). Does NOT call disconnectFromServer.
/// Safe when not connected (no-op).
void sendClientDisconnect(void);

/// YES if a TLS session is currently established.
BOOL isConnected(void);

/// Send SGP_C_LOGIN to begin the authentication handshake.
/// Protocol.m takes ownership of privKey and frees it in disconnectFromServer.
void startLogin(NSString *address, RSA *privKey, NSString *language);

/// Block until one message is received and dispatched.
/// Returns SGP_OK or an SGP_ERR_* code. Non-zero → stop the loop.
int handleMessage(void);

/// Send SGP_C_ACK for a delivered notification.
/// @param msgID   16-byte msg_id NSData from the notification dict.
/// @param status  0=delivered, 1=decrypt fail, 2=parse fail.
void ackNotification(NSData *msgID, int status);

/// Register a device token. Blocks up to 5s for server acknowledgement.
/// @param routingKey  32-byte SHA-256 of per-app secret K.
/// @param bundleId    App bundle identifier.
BOOL registerDeviceToken(NSData *routingKey, NSString *bundleId);

/// Send token feedback to the server (token invalid, app uninstalled, etc.)
/// @param routingKey  32-byte routing key.
/// @param type        Feedback type code.
/// @param reason      Human-readable reason (may be empty string).
void sendFeedback(NSData *routingKey, NSNumber *type, NSString *reason);

#endif /* SKYGLOW_PROTOCOL_H */