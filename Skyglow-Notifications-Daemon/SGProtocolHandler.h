#ifndef SKYGLOW_SG_PROTOCOL_HANDLER_H
#define SKYGLOW_SG_PROTOCOL_HANDLER_H

#import <Foundation/Foundation.h>
#import <openssl/rsa.h>

/** Wire Constants */
#define SGP_MAGIC               ((uint8_t)0x53)
#define SGP_VERSION             ((uint8_t)0x02)
#define SGP_HEADER_SIZE         8
#define SGP_MAX_PAYLOAD_LEN     4096

/** Timing (seconds) */
#define SGP_PONG_TIMEOUT_SEC       15
#define SGP_CHALLENGE_WINDOW_SEC  300

/** Fixed Field Lengths (bytes) */
#define SGP_ROUTING_KEY_LEN     32
#define SGP_MSG_ID_LEN          16
#define SGP_NONCE_LEN           32
#define SGP_PING_SEQ_LEN         8
#define SGP_GCM_IV_LEN          12
#define SGP_GCM_TAG_LEN         16

/**
 * S_NOTIFY payload layout offsets (byte positions within the payload).
 * Layout: routing_key(32) | msg_id(16) | seq(8) | expires_at(8) | flags(1) |
 *         content_type(1) | data_len(4) | data(data_len) | [iv(12) if encrypted]
 */
#define SGP_NOTIFY_OFF_ROUTING_KEY   0
#define SGP_NOTIFY_OFF_MSG_ID       32
#define SGP_NOTIFY_OFF_SEQ          48
#define SGP_NOTIFY_OFF_EXPIRES_AT   56
#define SGP_NOTIFY_OFF_FLAGS        64
#define SGP_NOTIFY_OFF_CONTENT_TYPE 65
#define SGP_NOTIFY_OFF_DATA_LEN     66
#define SGP_NOTIFY_OFF_DATA         70
#define SGP_NOTIFY_MIN_PAYLOAD      70

/** Return Codes for SGP_ProcessNextIncomingMessage */
#define SGP_OK           0
#define SGP_ERR_CLOSED   1
#define SGP_ERR_PROTO    2
#define SGP_ERR_IO       3
#define SGP_ERR_AUTH     4
#define SGP_ERR_TIMEOUT  5
#define SGP_ERR_REPLACED 6

typedef enum : uint8_t {
    SGP_S_HELLO          = 0x10,
    SGP_S_CHALLENGE      = 0x11,
    SGP_S_AUTH_OK        = 0x12,
    SGP_S_NOTIFY         = 0x13,
    SGP_S_DISCONNECT     = 0x14,
    SGP_S_TOKEN_ACK      = 0x15,
    SGP_S_PONG           = 0x16,
    SGP_S_POLL_DONE      = 0x17,
    SGP_S_REGISTER_OK    = 0x18,
    SGP_S_REGISTER_FAIL  = 0x19,
    SGP_S_PING           = 0x1A,
    SGP_S_TIME_SYNC      = 0x1B,

    SGP_C_LOGIN          = 0x20,
    SGP_C_LOGIN_RESP     = 0x21,
    SGP_C_POLL           = 0x22,
    SGP_C_ACK            = 0x23,
    SGP_C_DISCONNECT     = 0x24,
    SGP_C_REG_TOKEN      = 0x25,
    SGP_C_FILTER         = 0x2B,
    SGP_C_PING           = 0x27,
    SGP_C_REGISTER       = 0x28,
    SGP_C_REGISTER_RESP  = 0x29,
    SGP_C_PONG           = 0x2A,
} SGPMsgType;

typedef enum : uint8_t {
    SGP_DISC_NORMAL     = 0x00,
    SGP_DISC_AUTH_FAIL  = 0x01,
    SGP_DISC_PROTOCOL   = 0x02,
    SGP_DISC_SERVER_ERR = 0x03,
    SGP_DISC_REPLACED   = 0x04,
} SGPDisconnReason;

@protocol SGProtocolDelegate <NSObject>

/**
 * Called when the server delivers a push notification payload.
 */
- (void)protocolDidReceiveNotification:(NSDictionary *)notificationData;

/**
 * Called when the server sends the initial welcome challenge.
 */
- (void)protocolDidReceiveWelcomeChallenge;

/**
 * Called when authentication completes successfully.
 */
- (void)protocolDidAuthenticateSuccessfully;

/**
 * Called when the server acknowledges a token registration.
 */
- (void)protocolDidCompleteTokenRegistration:(NSString *)bundleIdentifier;

@optional

/**
 * Called when the server confirms all offline messages have been delivered.
 */
- (void)protocolDidFinishOfflineQueueDrain;

/**
 * Called when first-time registration completes successfully.
 * pemKey is a malloc'd, null-terminated PEM string. The delegate MUST call
 * SGP_ZeroAndFreeKeyMaterial(pemKey, len) after writing the key to its final
 * destination. The pointer is invalid after that call. It is NEVER safe to
 * let this pointer escape into an NSString or any other opaque object.
 */
- (void)protocolDidCompleteRegistrationWithAddress:(NSString *)address 
                                        privateKey:(char *)pemKey 
                                     serverVersion:(uint32_t)version;

/**
 * Called when first-time registration is rejected by the server.
 */
- (void)protocolDidFailRegistrationWithCode:(uint8_t)code reason:(NSString *)reason;

/**
 * Called when the server responds to a keep-alive ping.
 */
- (void)protocolDidReceiveKeepAlivePong;

/**
 * Called when the server sends a time synchronization message.
 */
- (void)protocolDidReceiveTimeSyncWithOffset:(int64_t)offsetSeconds;

@end

/** Key Material Helpers */

/**
 * Zeros and frees a malloc'd PEM buffer produced during registration.
 * The delegate MUST call this after writing the key to its final destination.
 * Passing NULL is safe (no-op).
 */
void SGP_ZeroAndFreeKeyMaterial(char *pemBuf, size_t len);

/** Public C-API */

/**
 * Sets the delegate that receives all protocol callbacks.
 */
void SGP_SetDelegate(id<SGProtocolDelegate> delegate);

/**
 * Returns YES if the SSL connection is active.
 */
BOOL SGP_IsConnected(void);

/**
 * Forcefully closes the socket to unblock any pending I/O without freeing SSL state.
 */
void SGP_AbortConnection(void);

/**
 * Establishes a TLS connection to the server using certificate pinning.
 */
int  SGP_ConnectToServer(const char *ip, int port, NSString *pinnedCert);

/**
 * Gracefully tears down the SSL session and frees all connection resources.
 */
void SGP_DisconnectFromServer(void);

/**
 * Sends a C_DISCONNECT frame with a normal reason code.
 */
void SGP_SendClientDisconnect(void);

/**
 * Initiates the first-time device registration flow.
 */
NSString *SGP_BeginFirstTimeRegistration(void);

/**
 * Begins the login handshake by sending C_LOGIN with the device address and key.
 */
void SGP_BeginLoginHandshake(NSString *address, RSA *privKey);

/**
 * Reads, validates, and dispatches one incoming server message.
 * Sends a keep-alive ping if the socket is idle for pingIntervalSec seconds.
 */
int  SGP_ProcessNextIncomingMessage(double pingIntervalSec);

/**
 * Synchronously registers a device token with the server, blocking up to 5 seconds.
 */
BOOL SGP_RegisterDeviceToken(NSData *routingKey, NSString *bundleID);

/**
 * Sends or persists an acknowledgement for a received notification.
 */
void SGP_EnqueueAcknowledgement(NSData *msgID, int status);

/**
 * Sends all persisted acknowledgements over the live connection.
 */
void SGP_FlushPendingAcknowledgements(void);

/**
 * Sends the active routing key filter to the server in chunked C_FILTER messages.
 */
void SGP_FlushActiveTopicFilter(void);

/**
 * Sends a C_POLL message to request any offline messages from the server.
 */
void SGP_RequestOfflineMessages(void);

/**
 * Returns the retry-after hint from the most recent S_DISCONNECT frame.
 */
uint32_t SGP_GetLastDisconnectRetryAfter(void);

#endif