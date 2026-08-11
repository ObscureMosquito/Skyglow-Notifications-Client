#ifndef SKYGLOW_SG_PROTOCOL_HANDLER_H
#define SKYGLOW_SG_PROTOCOL_HANDLER_H

#import <Foundation/Foundation.h>
#import <openssl/rsa.h>

/** Wire Constants */
#define SGP_MAGIC               ((uint8_t)0x53)
#define SGP_VERSION             ((uint8_t)0x02)
#define SGP_HEADER_SIZE         8
#define SGP_MAX_PAYLOAD_LEN     4096
#define SGP_SERVER_ADDRESS_MAX_BYTES 16
#define SGP_PONG_TIMEOUT_SEC       15
#define SGP_CHALLENGE_WINDOW_SEC  300
#define SGP_NET_OP_TIMEOUT_SEC      10
#define SGP_ROUTING_KEY_LEN     32
#define SGP_MSG_ID_LEN          16
#define SGP_NONCE_LEN           32
#define SGP_PING_SEQ_LEN         8
#define SGP_GCM_IV_LEN          12
#define SGP_GCM_TAG_LEN         16
#define SGP_NOTIFY_OFF_ROUTING_KEY   0
#define SGP_NOTIFY_OFF_MSG_ID       32
#define SGP_NOTIFY_OFF_SEQ          48
#define SGP_NOTIFY_OFF_EXPIRES_AT   56
#define SGP_NOTIFY_OFF_FLAGS        64
#define SGP_NOTIFY_OFF_CONTENT_TYPE 65
#define SGP_NOTIFY_OFF_DATA_LEN     66
#define SGP_NOTIFY_OFF_DATA         70
#define SGP_NOTIFY_MIN_PAYLOAD      70
#define SGP_NOTIFY_FLAG_ENCRYPTED   0x01
#define SGP_NOTIFY_FLAG_COMPRESSED  0x02
#define SGP_MAX_INFLATED_LEN        65536
#define SGP_OK                   0
#define SGP_ERR_CLOSED           1
#define SGP_ERR_PROTO            2
#define SGP_ERR_IO               3
#define SGP_ERR_AUTH             4
#define SGP_ERR_TIMEOUT          5
#define SGP_ERR_REPLACED         6
#define SGP_ERR_VERSION_MISMATCH 7
#define SGP_ACK_SUCCESS          0
#define SGP_ACK_DECRYPT_FAILED   1
#define SGP_ACK_PARSE_FAILED     2
#define SGP_ACK_EXPIRED          3

typedef enum : uint8_t {
    SGP_C_UPGRADE        = 0x00,
    SGP_S_HELLO          = 0x10,
    SGP_S_CHALLENGE      = 0x11,
    SGP_S_AUTH_OK        = 0x12,
    SGP_S_NOTIFY         = 0x13,
    SGP_S_DISCONNECT     = 0x14,
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
    SGP_C_FILTER         = 0x2B,
    SGP_C_PING           = 0x27,
    SGP_C_REGISTER       = 0x28,
    SGP_C_REGISTER_RESP  = 0x29,
    SGP_C_PONG           = 0x2A,
} SGPMsgType;

typedef enum : uint8_t {
    SGP_DISC_NORMAL           = 0x00,
    SGP_DISC_AUTH_FAIL        = 0x01,
    SGP_DISC_PROTOCOL         = 0x02,
    SGP_DISC_SERVER_ERR       = 0x03,
    SGP_DISC_REPLACED         = 0x04,
    SGP_DISC_VERSION_MISMATCH = 0x05,
} SGPDisconnReason;

@protocol SGProtocolDelegate <NSObject>

- (void)protocolDidReceiveNotification:(NSDictionary *)notificationData;
- (void)protocolDidReceiveWelcomeChallenge;
- (void)protocolDidAuthenticateSuccessfully;
- (void)protocolDidFinishOfflineQueueDrain;
- (void)protocolDidCompleteRegistrationWithAddress:(NSString *)address 
                                        privateKey:(char *)pemKey 
                                     serverVersion:(uint32_t)version;
- (void)protocolDidFailRegistrationWithCode:(uint8_t)code reason:(NSString *)reason;
- (void)protocolDidReceiveKeepAlivePong;
- (void)protocolDidReceiveTimeSyncWithOffset:(int64_t)offsetSeconds;

@end

void SGP_ZeroAndFreeKeyMaterial(char *pemBuf, size_t len);

/** Public C-API */

/** Sets the delegate that receives all protocol callbacks */
void SGP_SetDelegate(id<SGProtocolDelegate> delegate);
BOOL SGP_IsConnected(void);

/** Monotonically increasing identifier for the current connection attempt. */
uint64_t SGP_GetConnectionGeneration(void);

/** Forcefully closes the socket to unblock any pending I/O without freeing SSL state */
void SGP_AbortConnection(void);

/** Establishes a TLS connection to the server using certificate pinning. */
int  SGP_ConnectToServer(const char *ip, int port, NSString *pinnedCert);

/** Client identity presented during the TLS handshake */
void SGP_SetRegistrationIdentity(NSString *identityPEM);

/** Gracefully tears down the SSL session and frees all connection resources */
void SGP_DisconnectFromServer(void);

/** sends C_DISCONNECT */
BOOL SGP_SendClientDisconnect(void);

/** Initiates the first-time device registration flow */
BOOL SGP_BeginFirstTimeRegistration(void);

/** Pre-generates the registration keypair and caches it */
void SGP_PrepareRegistrationKeypair(void);

/** Begins the login handshake by sending C_LOGIN with the device address and key. */
void SGP_BeginLoginHandshake(NSString *address, RSA *privKey);

/** Reads, validates, and dispatches one incoming server message. */
int  SGP_ProcessNextIncomingMessage(double pingIntervalSec);

/** Returns a stable symbolic name for SGP_OK / SGP_ERR_* return codes. */
const char *SGP_ErrorName(int code);

/** Returns a stable symbolic name for SGP_ConnectToServer setup failures */
const char *SGP_ConnectErrorName(int code);

/** Sends or persists an acknowledgement for a received notification */
void SGP_EnqueueAcknowledgement(NSData *msgID, int status);

/** Sends all persisted acknowledgements over the live connection. */
void SGP_FlushPendingAcknowledgements(void);

/** Sends the complete registration set to the server in chunked C_FILTER messages.*/
void SGP_FlushActiveTopicFilter(void);

/** Sends a C_POLL message to request any offline messages from the server */
void SGP_RequestOfflineMessages(void);

/** Returns the retry-after hint from the most recent S_DISCONNECT frame */
uint32_t SGP_GetLastDisconnectRetryAfter(void);

/** Sends a keep-alive ping if connected and no ping is already pending */
BOOL SGP_SendKeepAlivePing(void);

/**
 * Returns the monotonic timestamp of the last received server frame,
 * or 0.0 if no frames have been received this connection.
 */
double SGP_GetLastFrameReceivedAt(void);

/**
 * Returns how many WALL-CLOCK seconds the current keep-alive ping has gone
 * unanswered, or 0.0 if no ping is pending.
 */
double SGP_GetPendingPingAgeWallSeconds(void);

/* Underlying TCP socket fd or -1 when not connected. */
int SGP_GetSocketFD(void);

#endif
