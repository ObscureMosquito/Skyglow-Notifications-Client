#ifndef SKYGLOW_PROTOCOL_H
#define SKYGLOW_PROTOCOL_H

/*
 * Protocol.h — Skyglow Notification Daemon
 * Skyglow Protocol version 2 (SGP/2)
 *
 * ═══════════════════════════════════════════════════════════════════════
 * WIRE FORMAT
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Every message in both directions uses an 8-byte fixed header:
 *
 * Offset  Size  Field
 * ──────  ────  ─────────────────────────────────────────────────
 * 0       1     magic       SGP_MAGIC (0x53 = 'S'). Wrong → close.
 * 1       1     version     SGP_VERSION (0x02). Unsupported → close.
 * 2       1     type        SGPMsgType enum value.
 * 3       1     flags       Reserved. Send 0x00, ignore unknown bits.
 * 4       4     payload_len Big-endian uint32. Must be ≤ SGP_MAX_PAYLOAD_LEN.
 * 8+      N     payload     Layout defined per type below.
 *
 * ═══════════════════════════════════════════════════════════════════════
 * AUTHENTICATION FLOW
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Client                               Server
 * ──────                               ──────
 * TCP + TLS connect ──────────────────>
 * <──────────────── S_HELLO  (server_version[4])
 * C_LOGIN ───────────────────────────> (addr_len[2]+addr+timestamp[8]+proto_ver[4])
 * <──────────────── S_CHALLENGE  (nonce[32])
 * C_LOGIN_RESP ──────────────────────> (timestamp[8]+sig_len[2]+sig[N])
 * <──────────────── S_AUTH_OK  — or — S_DISCONNECT(AuthFail)
 * C_POLL ────────────────────────────> (drain offline queue)
 * <──────────────── S_NOTIFY × N  (offline messages)
 * <──────────────── S_POLL_DONE   (queue empty)
 * … steady state …
 * <──────────────── S_PING  (seq[8])  server keepalive
 * C_PONG ────────────────────────────> (seq[8] echo)
 *
 * CHALLENGE-RESPONSE:
 * Server sends 32 random bytes (nonce) in S_CHALLENGE.
 * Client signs:  nonce[32] || device_address_utf8 || login_timestamp_be[8]
 * using RSA-PSS-SHA256. Server verifies with stored public key.
 * Timestamp must be within ±SGP_CHALLENGE_WINDOW_SEC of server time.
 *
 * CLOCK SKEW:
 * If auth fails due to suspected clock skew, server sends S_TIME_SYNC
 * immediately BEFORE S_DISCONNECT(AUTH_FAIL). Client compares the
 * server timestamp to local time; if |delta| > SGP_CHALLENGE_WINDOW_SEC,
 * it logs a clear warning rather than retrying endlessly.
 *
 * ═══════════════════════════════════════════════════════════════════════
 * SGP_S_NOTIFY PAYLOAD LAYOUT  (minimum SGP_NOTIFY_MIN_PAYLOAD = 70 bytes)
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Offset  Size  Field
 * ──────  ────  ──────────────────────────────────────────────────
 * 0      32    routing_key    SHA-256 of per-app secret K.
 * 32      16    msg_id         128-bit message ID, raw bytes.
 * 48       8    device_seq     Big-endian int64. Per-device sequence number.
 * Use for client-side deduplication.
 * 56       8    expires_at     Big-endian int64. Unix seconds; 0 = no expiry.
 * If non-zero and in the past, client MAY discard.
 * 64       1    flags          bit 0: is_encrypted  (SGP_NOTIFY_FLAG_ENCRYPTED)
 * bit 1: is_critical   (SGP_NOTIFY_FLAG_CRITICAL)
 * bypass Do-Not-Disturb / Critical Alert
 * bits 2–3: priority   (SGP_NOTIFY_GET_PRIORITY)
 * bits 4–7: reserved, ignore.
 * 65       1    payload_type   SGP_PAYLOAD_TYPE_BINARY (0x01) for TLV binary payloads. 
 * Reserved values 0x02–0xFF for future media types 
 * (JPEG, PNG, WebP, …). Clients MUST treat unrecognised 
 * values as an error and send C_ACK with status=1.
 * NOTE: SGP_PAYLOAD_TYPE_BINARY (0x01) is the only
 * value the server currently emits. Clients may
 * assert this and reject 0x00.
 * 66       4    data_len       Big-endian uint32.
 * 70      N     data           Plaintext OR ciphertext||GCM-tag[16].
 * When payload_type=BINARY: Custom TLV encoded data.
 * When encrypted: AES-256-GCM(TLV bytes)||tag[16].
 * 70+N    12    iv             AES-GCM nonce. Present only when is_encrypted=1.
 *
 * DEDUPLICATION (at-least-once delivery guarantee):
 * A notification may arrive more than once (connection dropped after
 * OS delivery but before C_ACK reached server). Client MUST maintain
 * a persisted cache of recently seen msg_id values (last 200 recommended)
 * and silently re-ACK duplicates without re-delivering to the OS.
 *
 * ═══════════════════════════════════════════════════════════════════════
 * SGP_S_DISCONNECT PAYLOAD  (5 bytes)
 * ═══════════════════════════════════════════════════════════════════════
 *
 * reason[1]         SGPDisconnReason code.
 * retry_after[4]    Big-endian uint32. Seconds to wait before reconnecting.
 * 0 = reconnect immediately (NORMAL, REPLACED).
 * SGP_DISCONNECT_NO_RETRY = do not reconnect automatically
 * (AUTH_FAIL, PROTOCOL — requires user intervention).
 * Client MUST use MAX(own_backoff, retry_after) as the actual sleep.
 *
 * ═══════════════════════════════════════════════════════════════════════
 * DISCONNECT REASON CODES
 * ═══════════════════════════════════════════════════════════════════════
 *
 * SGP_DISC_NORMAL     0x00  Voluntary clean close.
 * SGP_DISC_AUTH_FAIL  0x01  Bad signature or clock skew > 300s.
 * SGP_DISC_PROTOCOL   0x02  Malformed or unexpected message.
 * SGP_DISC_SERVER_ERR 0x03  Server error; use retry_after (5–35s jitter).
 * SGP_DISC_REPLACED   0x04  Newer connection replaced this one; reconnect now.
 *
 * ═══════════════════════════════════════════════════════════════════════
 * handleMessage() RETURN CODES
 * ═══════════════════════════════════════════════════════════════════════
 *
 * SGP_OK           0   Handled OK; keep calling.
 * SGP_ERR_CLOSED   1   Server disconnected; stop the loop.
 * SGP_ERR_PROTO    2   Protocol violation; close + reconnect.
 * SGP_ERR_IO       3   I/O error; close + reconnect.
 * SGP_ERR_AUTH     4   Auth failure; back off (see getLastDisconnRetryAfter).
 * SGP_ERR_TIMEOUT  5   Pong timeout; close + reconnect.
 * SGP_ERR_REPLACED 6   Replaced by newer connection. Reconnect immediately;
 * do NOT increment consecutive failure counter.
 *
 * ═══════════════════════════════════════════════════════════════════════
 * NOTIFICATION DELEGATE DICTIONARY KEYS
 * ═══════════════════════════════════════════════════════════════════════
 *
 * @"routing_key"   NSData (SGP_ROUTING_KEY_LEN bytes).  DB lookup key.
 * @"msg_id"        NSData (SGP_MSG_ID_LEN bytes).        Pass to ackNotification:.
 * @"device_seq"    NSNumber (int64).   Per-device sequence; use for dedup.
 * @"expires_at"    NSNumber (int64).   Unix seconds; 0 = never expires.
 * @"is_encrypted"  NSNumber (BOOL).
 * @"is_critical"   NSNumber (BOOL).    Bypass Do-Not-Disturb if YES.
 * @"priority"      NSNumber (uint8).   SGP_NOTIFY_PRIORITY_* value.
 * @"data"          NSData.             TLV binary bytes (plaintext) OR
 * ciphertext||GCM-tag (encrypted).
 * @"iv"            NSData (12 bytes).  Only present when is_encrypted=YES.
 *
 * The payload is a custom TLV binary object. Callers MUST parse @"data"
 * using the custom binary parser (after AES-GCM decryption when is_encrypted=YES).
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

#define SGP_MAGIC               ((uint8_t)0x53)
#define SGP_VERSION             ((uint8_t)0x02)
#define SGP_HEADER_SIZE         8
#define SGP_MAX_PAYLOAD_LEN     4096

/* ─────────────────────────────────────────────────────────────────
 * Timing (seconds)
 * ───────────────────────────────────────────────────────────────── */

#define SGP_PING_INTERVAL_SEC      900
#define SGP_PONG_TIMEOUT_SEC       15
#define SGP_CHALLENGE_WINDOW_SEC  300

/* ─────────────────────────────────────────────────────────────────
 * Fixed field lengths (bytes)
 * ───────────────────────────────────────────────────────────────── */

#define SGP_ROUTING_KEY_LEN     32
#define SGP_MSG_ID_LEN          16
#define SGP_NONCE_LEN           32
#define SGP_PING_SEQ_LEN         8
#define SGP_GCM_IV_LEN          12
#define SGP_GCM_TAG_LEN         16
#define SGP_COLLAPSE_KEY_LEN    16   ///< Optional collapse key (apns-collapse-id equiv.)

/* ─────────────────────────────────────────────────────────────────
 * S_NOTIFY field offsets and minimum payload size
 * ───────────────────────────────────────────────────────────────── */

#define SGP_NOTIFY_OFF_ROUTING_KEY    0
#define SGP_NOTIFY_OFF_MSG_ID        32
#define SGP_NOTIFY_OFF_DEVICE_SEQ    48   ///< big-endian int64
#define SGP_NOTIFY_OFF_EXPIRES_AT    56   ///< big-endian int64; 0 = no expiry
#define SGP_NOTIFY_OFF_FLAGS         64
#define SGP_NOTIFY_OFF_PAYLOAD_TYPE  65   ///< SGP_PAYLOAD_TYPE_BINARY (0x01). See payload_type docs.
#define SGP_NOTIFY_OFF_CONTENT_TYPE  SGP_NOTIFY_OFF_PAYLOAD_TYPE  ///< backward-compat alias
#define SGP_NOTIFY_OFF_DATA_LEN      66   ///< big-endian uint32
#define SGP_NOTIFY_OFF_DATA          70
#define SGP_NOTIFY_MIN_PAYLOAD       70   ///< Minimum valid S_NOTIFY payload

/* ─────────────────────────────────────────────────────────────────
 * S_NOTIFY flags byte
 * ───────────────────────────────────────────────────────────────── */

#define SGP_NOTIFY_FLAG_ENCRYPTED   0x01  ///< bit 0: AES-256-GCM encrypted
#define SGP_NOTIFY_FLAG_CRITICAL    0x02  ///< bit 1: bypass DND / Critical Alert

#define SGP_NOTIFY_PRIORITY_MASK    0x0C  ///< bits 2–3: priority
#define SGP_NOTIFY_PRIORITY_SHIFT   2

#define SGP_NOTIFY_PRIORITY_NORMAL   0
#define SGP_NOTIFY_PRIORITY_HIGH     1
#define SGP_NOTIFY_PRIORITY_CRITICAL 2

/// Extract 2-bit priority from a flags byte.
#define SGP_NOTIFY_GET_PRIORITY(flags) \
    (((flags) & SGP_NOTIFY_PRIORITY_MASK) >> SGP_NOTIFY_PRIORITY_SHIFT)

/* ─────────────────────────────────────────────────────────────────
 * payload_type byte (S_NOTIFY offset 65)
 *
 * Identifies how to interpret the data[] field of S_NOTIFY.
 *
 * SGP_PAYLOAD_TYPE_BINARY (0x01) is the only value the server currently
 * emits. The data[] field always contains a custom TLV binary payload; after
 * AES-GCM decryption (when is_encrypted=1) the plaintext is likewise
 * a custom TLV binary payload.
 *
 * Values 0x02 and above are reserved for future media payloads
 * (JPEG thumbnails, PNG icons, WebP attachments, etc.). Clients that
 * receive an unrecognised payload_type MUST ACK with status=1 (error)
 * and not attempt to deliver the notification to the OS.
 *
 * NOTE: 0x00 is intentionally unused and treated as an error by
 * current clients, so that a zero-initialised byte never silently
 * succeeds. This prevents the class of bug where a missing field
 * defaulted to 0 (CT_PLIST) and caused parse failures on the client.
 * ───────────────────────────────────────────────────────────────── */

#define SGP_PAYLOAD_TYPE_BINARY   0x01   ///< Custom TLV binary payload. Always use this.
// 0x02–0xFF reserved for future media types (images, etc.)

// Backward-compatibility aliases — do not use in new code.
#define SGP_CONTENT_TYPE_PLIST  0x00   ///< DEPRECATED. Never emitted by server.
#define SGP_CONTENT_TYPE_BINARY SGP_PAYLOAD_TYPE_BINARY

/* ─────────────────────────────────────────────────────────────────
 * S_DISCONNECT retry_after sentinel
 * ───────────────────────────────────────────────────────────────── */

/// Sent with AUTH_FAIL and PROTOCOL: do not reconnect automatically.
#define SGP_DISCONNECT_NO_RETRY  ((uint32_t)0xFFFFFFFF)

/* ─────────────────────────────────────────────────────────────────
 * Message types
 * ───────────────────────────────────────────────────────────────── */

typedef enum : uint8_t {

    /* Server → Client */
    SGP_S_HELLO          = 0x10,
    SGP_S_CHALLENGE      = 0x11,
    SGP_S_AUTH_OK        = 0x12,
    SGP_S_NOTIFY         = 0x13,
    SGP_S_DISCONNECT     = 0x14,
    SGP_S_TOKEN_ACK      = 0x15,
    SGP_S_PONG           = 0x16,
    SGP_S_POLL_DONE      = 0x17,   ///< Offline queue flushed; empty payload
    SGP_S_REGISTER_OK    = 0x18,   ///< Device registration accepted
    SGP_S_REGISTER_FAIL  = 0x19,   ///< Device registration rejected
    SGP_S_PING           = 0x1A,   ///< Server keepalive; seq[8]. MUST respond with C_PONG.
    SGP_S_TIME_SYNC      = 0x1B,   ///< Clock hint before AUTH_FAIL; server_time[8] i64

    /* Client → Server */
    SGP_C_LOGIN          = 0x20,
    SGP_C_LOGIN_RESP     = 0x21,
    SGP_C_POLL           = 0x22,
    SGP_C_ACK            = 0x23,
    SGP_C_DISCONNECT     = 0x24,
    SGP_C_REG_TOKEN      = 0x25,
    SGP_C_FILTER         = 0x2B,
    SGP_C_PING           = 0x27,
    SGP_C_REGISTER       = 0x28,   ///< Begin device registration (no device_address yet)
    SGP_C_REGISTER_RESP  = 0x29,   ///< Registration challenge response
    SGP_C_PONG           = 0x2A,   ///< Response to SGP_S_PING; MUST echo seq[8]

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

#define SGP_OK           0
#define SGP_ERR_CLOSED   1
#define SGP_ERR_PROTO    2
#define SGP_ERR_IO       3
#define SGP_ERR_AUTH     4
#define SGP_ERR_TIMEOUT  5
#define SGP_ERR_REPLACED 6   ///< Reconnect immediately; do NOT increment failures.

/* ─────────────────────────────────────────────────────────────────
 * Notification delegate
 * ───────────────────────────────────────────────────────────────── */

@protocol NotificationDelegate <NSObject>
- (void)processNotificationMessage:(NSDictionary *)notificationData;
- (void)handleWelcomeMessage;
- (void)authenticationSuccessful;
- (void)deviceTokenRegistrationCompleted:(NSString *)bundleId;
@optional
/// Called when SGP_S_POLL_DONE is received (offline queue fully drained).
- (void)offlineQueueDrainCompleted;
/// Called on SGP_S_REGISTER_OK.
/// @param deviceAddress  The address the server accepted (same as proposed).
/// @param privateKeyPEM  PEM-encoded RSA private key. Caller must persist it.
/// @param serverVersion  Server protocol version from the OK payload.
- (void)registrationCompleted:(NSString *)deviceAddress
                   privateKey:(NSString *)privateKeyPEM
                serverVersion:(uint32_t)serverVersion;
/// Called on SGP_S_REGISTER_FAIL.
/// @param reasonCode  Server reason code byte.
/// @param reason      Human-readable reason string from server.
- (void)registrationFailed:(uint8_t)reasonCode reason:(NSString *)reason;
/// Called when SGP_S_PONG is received to tell the Growth Algorithm to increase the interval.
- (void)keepAlivePingSucceeded;
@end

/* ─────────────────────────────────────────────────────────────────
 * Public API
 * ───────────────────────────────────────────────────────────────── */

/// Set the delegate. Call before connectToServer.
void setNotificationDelegate(id<NotificationDelegate> delegate);

/// Begin first-time device registration on an already-connected session.
/// Generates a fresh RSA-2048 keypair, proposes a UUID device address, and
/// sends SGP_C_REGISTER. The server will respond with SGP_S_CHALLENGE, then
/// SGP_S_REGISTER_OK or SGP_S_REGISTER_FAIL, both handled in handleMessage().
///
/// On SGP_S_REGISTER_OK:
///   1. The delegate receives registrationCompleted:privateKey:serverVersion:.
///   2. The caller persists the profile (device_address, privateKey, server_address).
///   3. The caller immediately calls startLogin() on the same connection —
///      the server has reset its state to CONNECTED and expects C_LOGIN next.
///
/// On SGP_S_REGISTER_FAIL:
///   The delegate receives registrationFailed:reason:.
///
/// Returns the proposed device address so the caller can store it on success,
/// or nil on failure (key generation failed or not connected).
NSString *startRegistration(void);

/// Establish TLS to serverIP:port, pinning the PEM certificate string.
/// Returns 0 on success, negative on failure.
int connectToServer(const char *serverIP, int port, NSString *serverCert);

/// Tear down TLS and release all SSL state. Safe when not connected.
void disconnectFromServer(void);

/// Send SGP_C_DISCONNECT(Normal). Does NOT call disconnectFromServer.
void sendClientDisconnect(void);

/// YES if a TLS session is currently established.
BOOL isConnected(void);

/// Send SGP_C_LOGIN to begin the authentication handshake.
/// Protocol.m takes ownership of privKey and frees it in disconnectFromServer.
void startLogin(NSString *address, RSA *privKey, NSString *language);

/// Block until one message is received and dispatched.
/// pingIntervalSec dynamically changes based on the Growth Algorithm.
int handleMessage(double pingIntervalSec);

/// Send SGP_C_ACK for a delivered notification.
void ackNotification(NSData *msgID, int status);

/// Register a device token. Blocks up to 5s for server acknowledgement.
BOOL registerDeviceToken(NSData *routingKey, NSString *bundleId);

/// Flushes any pending ACKs from the DB to the server.
void flushPendingACKs(void);

/// Streams all active routing keys to the server using chunked SGP_C_FILTER packets.
void flushActiveTopicFilter(void);

/// Returns the retry_after value from the most recent SGP_S_DISCONNECT.
/// Call this after handleMessage() returns any non-zero result code.
///
///   0                     = reconnect immediately
///   SGP_DISCONNECT_NO_RETRY = do not reconnect without user action
///   other                 = minimum seconds to wait before reconnecting
///
/// Caller should use MAX(own_backoff, getLastDisconnRetryAfter()),
/// capped at MAX_BACKOFF_SEC.
uint32_t getLastDisconnRetryAfter(void);

/// Send SGP_C_ACK for a delivered notification (queues it in the DB first).
void ackNotification(NSData *msgID, int status);

/// Flushes any pending ACKs from the DB to the server.
void flushPendingACKs(void);

#endif /* SKYGLOW_PROTOCOL_H */