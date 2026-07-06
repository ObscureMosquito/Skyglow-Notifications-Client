#ifndef SKYGLOW_SG_CONTROL_CHANNEL_PROTOCOL_H
#define SKYGLOW_SG_CONTROL_CHANNEL_PROTOCOL_H

#import <Foundation/Foundation.h>
#import <mach/mach.h>

/* Charset validator for identifier-shaped wire strings (bundle IDs, server
 * addresses) received over IPC.  Allows the conservative reverse-DNS /
 * DNS-label charset: alphanumerics, dot, hyphen, underscore.  Rejects
 * empty strings, anything over 255 bytes, path separators, control chars,
 * format specifiers, whitespace, and embedded NULs — all of which are
 * invalid in any legitimate bundle ID or DNS-style server address and
 * would otherwise have to be defended against by every downstream
 * consumer.  Defense at the IPC boundary, applied uniformly. */
static inline BOOL SG_IsIdentifierStringSafe(NSString *str) {
    if (!str) return NO;
    NSUInteger len = [str lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    if (len == 0 || len > 255) return NO;
    const char *bytes = [str UTF8String];
    if (!bytes) return NO;
    for (NSUInteger i = 0; i < len; i++) {
        unsigned char c = (unsigned char)bytes[i];
        BOOL ok = (c >= 'A' && c <= 'Z') ||
                  (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') ||
                  c == '.' || c == '_' || c == '-';
        if (!ok) return NO;
    }
    return YES;
}

/**
 * SGControlChannel wire protocol.
 *
 * One persistent Mach connection per peer pair carries every cross-process
 * control message in this project: token requests, push delivery into
 * SpringBoard, configuration reloads, debug injection, FSM state broadcasts,
 * and the subscription/event machinery that replaces ad-hoc Darwin
 * notifications.  All payloads ride inside a single envelope struct; the
 * envelope is a fully-formed Mach simple message (no port descriptors beyond
 * the reply port carried in msgh_local_port).
 *
 * Two named services define the two roles a process can play.  The daemon
 * advertises SKYGLOW_CONTROL_SERVICE_DAEMON and clients (prefs bundle,
 * SpringBoard tweak) connect to it.  The SpringBoard tweak additionally
 * advertises SKYGLOW_CONTROL_SERVICE_SPRINGBOARD which the daemon connects to
 * when it needs to push a notification — the daemon is a client of the tweak
 * for that one direction.  Either side can subscribe to events from the other
 * once a connection is up; subscriptions live for the connection lifetime.
 *
 * Designed to run unchanged from iOS 3 upward: pure Mach IPC, no XPC, no
 * dispatch sources required at the wire level, no API gated on a later iOS.
 */

/** Mach Service Names */

/**
 * Advertised by the daemon.  Token requests, feedback, configuration
 * reloads, debug injection, and all event subscriptions land here.
 */
#define SKYGLOW_CONTROL_SERVICE_DAEMON       "com.skyglow.sgn.control.daemon"

/**
 * Advertised by the SpringBoard tweak.  The daemon connects to this service
 * to deliver notifications.  Kept distinct from the daemon-side service so
 * each side owns its own lookup and dead-name lifecycle.
 */
#define SKYGLOW_CONTROL_SERVICE_SPRINGBOARD  "com.skyglow.sgn.control.springboard"

/** Protocol Identity */

/**
 * Magic byte at the head of every envelope.  Lets a receiver reject foreign
 * traffic that somehow lands on the port before the bootstrap_check_in handoff
 * is complete.
 */
#define SG_CONTROL_MAGIC                     ((uint8_t)0x43)  /* 'C' */

/**
 * Current wire version.  Servers reject mismatching versions with
 * SGCERR_INVALID_REQUEST; the client is expected to be at the same or older
 * version as the daemon it talks to.  Bump when the envelope or any payload
 * struct changes in a non-additive way.
 */
#define SG_CONTROL_VERSION                   ((uint8_t)0x01)

/** Size Bounds */

/**
 * Maximum bytes carried in the variable payload region of one envelope.
 * Sized to comfortably fit the largest current payload (push delivery with a
 * 1 KiB serialised plist) with room for future growth.  Larger payloads must
 * be chunked across multiple envelopes by the caller — the channel itself
 * delivers one envelope atomically per send.
 */
#define SG_CONTROL_MAX_PAYLOAD               4096

#define SG_CONTROL_MAX_TOKEN_SIZE            48
#define SG_CONTROL_MAX_BUNDLE_ID_SIZE        256
#define SG_CONTROL_MAX_REASON_SIZE           64
#define SG_CONTROL_MAX_USERINFO_SIZE         3072
#define SG_CONTROL_MAX_ERROR_DETAIL_SIZE     256
#define SG_CONTROL_MAX_EVENT_DATA_SIZE       1024
#define SG_CONTROL_MAX_SERVER_ADDRESS_SIZE   256
#define SG_CONTROL_MAX_PROFILE_PEM_SIZE      3584

/** Timing Bounds */

/**
 * Canonical per-request timeout, applied when a caller passes 0 to
 * SGControlChannel's sendRequest:.  5 s is comfortable for a local Mach
 * round-trip on a healthy system and surfaces a stuck peer quickly enough
 * to retry within a user's attention window.  Callers wanting the default
 * should pass 0 rather than this constant, so a future tweak to the
 * default value propagates without touching call sites.
 */
#define SG_CONTROL_DEFAULT_REQUEST_TIMEOUT_SEC  5.0

/* Timeout for the prefs→daemon DELETE_APP roundtrip.  The daemon's own
 * handler dispatches a RESET_APP_REGISTRATION to the SB tweak first
 * (channel default 5s) and only replies success when SB confirms — so
 * the prefs-side bound must accommodate that 5s plus the daemon's own
 * processing plus a buffer for SB being briefly busy.  12s is "comfortably
 * over the worst case I've measured" rather than a value forced by
 * anything mechanical; ratchet down if cellular RTT becomes negligible. */
#define SG_CONTROL_DELETE_APP_TIMEOUT_SEC       12.0

/**
 * Mach send timeout for outbound envelopes (responses and events) — the
 * state queue must never block longer than this on a slow peer.
 */
#define SG_CONTROL_SEND_TIMEOUT_MS              1000

/** Message Types */

/**
 * Top-level wire opcode carried in SGControlMessageHeader.messageType.
 * Numeric ranges are reserved per category so new entries land in the same
 * neighbourhood as existing ones:
 *   0x10–0x2F  requests (client → server, expects a response)
 *   0x30–0x3F  responses (server → client, correlated by requestId)
 *   0x40–0x4F  events (unsolicited, server → client over a subscription)
 */
typedef enum : uint8_t {
    /* Requests */
    SGCMSG_TOKEN_REQUEST       = 0x10,  /* SGCTokenRequestPayload    */
    /* 0x12 RESERVED — was SGCMSG_FEEDBACK; uninstall now routes through
     * SGCMSG_DELETE_APP, no remaining callers.  Opcode kept reserved to
     * avoid silent collisions if reintroduced. */
    SGCMSG_RELOAD_CONFIG       = 0x13,  /* (empty payload)           */
    SGCMSG_TEST_INJECT         = 0x14,  /* (empty payload)           */
    SGCMSG_PUSH_DELIVERY       = 0x16,  /* SGCPushDeliveryPayload    */
    SGCMSG_SUBSCRIBE           = 0x17,  /* SGCSubscribePayload       */
    SGCMSG_UNSUBSCRIBE         = 0x18,  /* SGCUnsubscribePayload     */
    SGCMSG_REGISTER_INPUT_APP  = 0x19,  /* SGCBundleIdPayload — debug-only path (SNDebugViewController) */
    SGCMSG_UNREGISTER_INPUT_APP= 0x1A,  /* DEPRECATED — superseded by SGCMSG_DELETE_APP; opcode reserved */

    /* Unified per-app state commands sent from the prefs bundle to the
     * daemon.  Plist remains the user-state SSOT (written by prefs); these
     * messages tell the daemon to sync its DB + server filter accordingly.
     * See DOCUMENTATION.md for the full architecture. */
    SGCMSG_ENABLE_APP          = 0x1B,  /* SGCBundleIdPayload — mint token if absent + clear mute + flush filter */
    SGCMSG_DISABLE_APP         = 0x1C,  /* SGCBundleIdPayload — set mute + flush filter */
    SGCMSG_DELETE_APP          = 0x1D,  /* SGCBundleIdPayload — drop DB row + flush filter + ask SB to natively deregister */

    /* Daemon -> SB tweak: SB-side action requested by the daemon as part of
     * a DELETE_APP cascade.  Tells the SB tweak to reset iOS's view of the
     * app's push registration (via unregisterApplication: on classic, or
     * invalidateToken… on iOS 9+) so the app's next register call hits our
     * hook fresh.  Keeps SB-facing iOS calls inside the SB tweak. */
    SGCMSG_RESET_APP_REGISTRATION = 0x1E, /* SGCBundleIdPayload */

    /* Prefs -> SB tweak: request the list of bundles iOS currently considers
     * push-registered (third-party apps only).  Reply uses
     * SGCMSG_BUNDLE_ID_LIST as the response type with the list payload below.
     * Prefs filters out anything in its own Skyglow plist; the rest are the
     * "Apple Push" apps shown in the manual-forget section of the app list. */
    SGCMSG_LIST_PUSH_REGISTERED_APPS = 0x1F, /* (empty payload) */

    /* Prefs -> daemon: request the current SGStatusPayload snapshot.  Reply
     * is SGCMSG_STATUS_RESPONSE.  Independent of SGCEVT_STATE_CHANGED — that
     * event covers future changes; this message covers "what's the state
     * right now" (used to seed the UI on bundle load). */
    SGCMSG_QUERY_STATUS        = 0x20,  /* (empty payload) */

    /* Prefs -> daemon: delete a profile slot.  Atomic plist + keychain
     * removal owned by the daemon — prefs only requests, daemon does
     * everything.  If the active profile is deleted, the daemon also
     * disables itself and clears any pending state for that profile.
     * Payload is SGCProfileIndexPayload. */
    SGCMSG_DELETE_PROFILE      = 0x21,  /* SGCProfileIndexPayload */

    /* Prefs -> daemon: create or edit a profile slot.  The daemon owns the
     * profile plist and certificate file write.  Payload is
     * SGCProfileSavePayload; certificatePEMLength may be zero for an
     * address-only edit that preserves the existing certificate. */
    SGCMSG_SAVE_PROFILE        = 0x22,  /* SGCProfileSavePayload */

    /* Prefs -> daemon: switch the active profile slot.  Daemon writes the
     * activeProfile key in main prefs, reloads from disk, and triggers the
     * FSM reconnect cascade (Connected → ResolvingDNS) so the new server's
     * connection is attempted immediately.  Payload is SGCProfileIndexPayload. */
    SGCMSG_SET_ACTIVE_PROFILE  = 0x23,  /* SGCProfileIndexPayload */

    /* Prefs -> daemon: flip the global "enabled" switch.  The daemon owns the
     * write of the `enabled` key in main prefs (so it is the sole writer of the
     * keys it consumes), then reloads config and drives the FSM enable/disable
     * cascade.  Replaces the prefs bundle writing the plist directly and posting
     * SGCMSG_RELOAD_CONFIG.  Payload is SGCEnabledPayload. */
    SGCMSG_SET_ENABLED         = 0x24,  /* SGCEnabledPayload */

    /* Generic persisted intent emitted by a platform adapter when the user
     * chooses the platform's native push provider.  This removes appStatus
     * without invoking any SpringBoard-specific cleanup. */
    SGCMSG_CLEAR_APP_INTENT    = 0x25,  /* SGCBundleIdPayload */

    /* Preference UI -> daemon: persist the status-indicator preference. */
    SGCMSG_SET_STATUS_BAR_ENABLED = 0x26, /* SGCEnabledPayload */

    /* Responses */
    SGCMSG_GENERIC_ACK         = 0x30,  /* (empty payload)           */
    SGCMSG_TOKEN_RESPONSE      = 0x31,  /* SGCTokenResponsePayload   */
    SGCMSG_ERROR_RESPONSE      = 0x32,  /* SGCErrorResponsePayload   */
    SGCMSG_BUNDLE_ID_LIST      = 0x33,  /* SGCBundleIdListPayload    */
    SGCMSG_STATUS_RESPONSE     = 0x34,  /* SGStatusPayload (verbatim) */

    /* Events */
    SGCMSG_EVENT_DELIVERY      = 0x40,  /* SGCEventDeliveryPayload   */
} SGControlMessageType;

/** Event Types */

/**
 * Carried inside SGCEventDeliveryPayload.eventType.  Subscriptions target
 * one event type at a time; a client wanting several events sends several
 * SUBSCRIBE requests and receives independent subscription IDs back.
 */
typedef enum : uint16_t {
    SGCEVT_STATE_CHANGED      = 1,  /* SGStatusPayload (full snapshot) */
    SGCEVT_SB_RECEIVER_READY  = 2,  /* (empty data)             */
    SGCEVT_CONFIG_RELOADED    = 4,  /* (empty data)             */
} SGControlEventType;

/** Error Codes */

/**
 * Carried in SGControlMessageHeader.errorCode for ERROR_RESPONSE messages
 * and surfaced to callers of the client API.  DAEMON_DISABLED is the one a
 * caller must treat as terminal: the user has deliberately turned the
 * service off and a queue/retry would loop forever.  Every other code is
 * recoverable.
 */
typedef enum : uint16_t {
    SGCERR_OK                = 0,
    SGCERR_DAEMON_DISABLED   = 1,  /* user turned the daemon off in settings */
    SGCERR_UNREACHABLE       = 2,  /* peer not running or bootstrap lookup failed */
    SGCERR_TIMEOUT           = 3,  /* no response within the caller's budget */
    SGCERR_INVALID_REQUEST   = 4,  /* bad magic, version, type, or payload length */
    SGCERR_UNAUTHORIZED      = 5,  /* sender lacks capability for this request */
    SGCERR_INTERNAL          = 6,  /* server-side failure, retryable */
    SGCERR_DAEMON_BUSY       = 7,  /* server queue full; back off and retry */
    SGCERR_NOT_FOUND         = 8,  /* request references an entity that does not exist */
} SGControlError;

#pragma pack(4)

/** Wire Envelope */

/**
 * Every message on the channel is exactly this struct.  Variable payloads
 * fit inside payload[]; payloadLength records the populated prefix.  The
 * Mach header carries the reply port for requests in msgh_local_port and
 * the remote port (server or subscriber) in msgh_remote_port.
 *
 * subscriptionId is meaningful for SUBSCRIBE responses (server-assigned ID
 * the client uses for UNSUBSCRIBE), for UNSUBSCRIBE requests, and for
 * EVENT_DELIVERY (lets the client route the event to the right handler if
 * it has multiple subscriptions).  Zero otherwise.
 *
 * requestId is allocated monotonically by the requester and echoed back in
 * the matching response.  Zero on unsolicited events.
 */
typedef struct {
    mach_msg_header_t mach_header;
    mach_msg_body_t   mach_body;

    uint8_t  magic;            /* SG_CONTROL_MAGIC */
    uint8_t  version;          /* SG_CONTROL_VERSION */
    uint8_t  flags;            /* reserved in v1, must be 0 */
    uint8_t  messageType;      /* SGControlMessageType */

    uint16_t eventType;        /* SGControlEventType; only set on EVENT_DELIVERY */
    uint16_t errorCode;        /* SGControlError; only set on ERROR_RESPONSE */

    uint64_t requestId;        /* correlates request ↔ response; 0 on events */
    uint64_t subscriptionId;   /* identifies a subscription; see above */

    uint32_t payloadLength;    /* bytes used in payload[] */
    uint8_t  payload[SG_CONTROL_MAX_PAYLOAD];
} SGControlChannelMessage;

/** Payload Structs */

/**
 * SGCMSG_TOKEN_REQUEST.
 *
 * Client asks the daemon to mint a push token for the given bundle
 * identifier.  Server replies with TOKEN_RESPONSE on success or
 * ERROR_RESPONSE otherwise.
 */
typedef struct {
    char bundleID[SG_CONTROL_MAX_BUNDLE_ID_SIZE];
} SGCTokenRequestPayload;

/**
 * SGCMSG_TOKEN_RESPONSE.
 *
 * Server's reply to a successful TOKEN_REQUEST.  tokenLength is the
 * populated prefix of tokenData; values larger than SG_CONTROL_MAX_TOKEN_SIZE
 * must never be sent and must be rejected by the receiver.
 */
typedef struct {
    uint32_t tokenLength;
    uint8_t  tokenData[SG_CONTROL_MAX_TOKEN_SIZE];
} SGCTokenResponsePayload;

/**
 * SGCMSG_PUSH_DELIVERY.
 *
 * Sent by the daemon to the SpringBoard tweak with one decrypted notification
 * ready for the user.  userInfoData is a binary plist encoding the parsed
 * notification dictionary; userInfoLength is its byte count.  The tweak
 * replies with GENERIC_ACK on successful surfacing or ERROR_RESPONSE so the
 * daemon can decide whether to retry, treat as terminal, or expire.
 */
typedef struct {
    char     bundleID[SG_CONTROL_MAX_BUNDLE_ID_SIZE];
    uint32_t userInfoLength;
    uint8_t  userInfoData[SG_CONTROL_MAX_USERINFO_SIZE];
} SGCPushDeliveryPayload;

/**
 * SGCMSG_SUBSCRIBE.
 *
 * Client asks the server to start delivering events of the given type to
 * this connection.  Server responds with a GENERIC_ACK whose
 * subscriptionId is the handle to pass to UNSUBSCRIBE later.  Multiple
 * subscriptions to the same event type are allowed and each receives a
 * distinct id.
 */
typedef struct {
    uint16_t eventType;        /* SGControlEventType */
} SGCSubscribePayload;

/**
 * SGCMSG_UNSUBSCRIBE.
 *
 * Cancels a subscription previously created via SUBSCRIBE.  Unknown IDs
 * elicit GENERIC_ACK rather than an error — the operation is idempotent.
 */
typedef struct {
    uint64_t subscriptionId;
} SGCUnsubscribePayload;

/**
 * SGCMSG_REGISTER_INPUT_APP, SGCMSG_UNREGISTER_INPUT_APP.
 *
 * Posted by the prefs bundle to the SpringBoard tweak when the user adds or
 * removes an app from the Skyglow-handled list.  Replaces the legacy
 * com.skyglow.sgn.{,un}registerInputApp Darwin notifications, which used a
 * prefs-plist write to smuggle the bundle id alongside the signal.  The
 * channel carries the bundle id inline so no plist round-trip is needed.
 */
typedef struct {
    char bundleID[SG_CONTROL_MAX_BUNDLE_ID_SIZE];
} SGCBundleIdPayload;

/**
 * SGCMSG_DELETE_PROFILE payload.  Profile indices are 1..5; out-of-range
 * values are rejected by the daemon as SGCERR_INVALID_REQUEST.
 */
typedef struct {
    uint8_t profileIndex;
} SGCProfileIndexPayload;

/**
 * SGCMSG_SET_ENABLED payload.  Non-zero enables the daemon, zero disables it.
 */
typedef struct {
    uint8_t enabled;
} SGCEnabledPayload;

/**
 * SGCMSG_SAVE_PROFILE payload.  profileIndex is 1..5.  serverAddress is a
 * null-terminated UTF-8 hostname/IP string.  certificatePEMLength may be 0
 * to keep the profile's existing certificate, otherwise certificatePEM holds
 * a UTF-8 PEM certificate to install for this specific profile.
 */
typedef struct {
    uint8_t  profileIndex;
    uint8_t  reserved;
    uint16_t certificatePEMLength;
    char     serverAddress[SG_CONTROL_MAX_SERVER_ADDRESS_SIZE];
    uint8_t  certificatePEM[SG_CONTROL_MAX_PROFILE_PEM_SIZE];
} SGCProfileSavePayload;

/**
 * SGCMSG_BUNDLE_ID_LIST (response).
 *
 * Packed list of bundle identifiers — variable-length encoding to avoid
 * wasting 256 bytes per slot on entries that average ~30 characters.
 *
 * Wire layout:
 *   uint16_t count         (BE-on-the-wire if cross-arch is ever a concern,
 *                          but the channel is in-host so native order)
 *   followed by `count` entries, each:
 *     uint16_t bundleIdLen
 *     uint8_t  bundleId[bundleIdLen]   (UTF-8, NOT null-terminated)
 *
 * Total serialized size must fit SG_CONTROL_MAX_PAYLOAD (4096).  With ~30-byte
 * bundle IDs that's ~120 entries; enough for any realistic device.  If we
 * ever exceed it we'll add chunking the way C_FILTER does.
 *
 * Consumers MUST iterate strictly via the encoded lengths — never assume
 * null termination.
 */
typedef struct {
    uint16_t count;
    uint8_t  data[];  /* flexible array — entries packed as documented above */
} SGCBundleIdListPayload;

/**
 * SGCMSG_EVENT_DELIVERY.
 *
 * Server-initiated message sent to one subscriber.  eventType identifies the
 * event family; data carries the event-specific struct (one of the
 * SGCxxxEventData types below).  dataLength records the populated prefix.
 * subscriptionId in the envelope identifies which subscription this
 * delivery belongs to, so a client with several subscriptions can route
 * correctly.
 */
typedef struct {
    uint16_t eventType;        /* SGControlEventType */
    uint32_t dataLength;
    uint8_t  data[SG_CONTROL_MAX_EVENT_DATA_SIZE];
} SGCEventDeliveryPayload;

/**
 * SGCMSG_ERROR_RESPONSE.
 *
 * Sent in place of any normal response when an error occurs.  The numeric
 * SGControlError is carried in the envelope's errorCode field; this payload
 * carries an optional human-readable string for logging.  Callers branch on
 * the numeric code; the message is for diagnostics only.
 */
typedef struct {
    char message[SG_CONTROL_MAX_ERROR_DETAIL_SIZE];
} SGCErrorResponsePayload;

/* SGCEVT_STATE_CHANGED carries the full SGStatusPayload (from SGStatusServer.h)
 * as its event data — subscribers get the same snapshot the unix status sock
 * would have served, with no separate query round-trip. */

#pragma pack()

#endif
