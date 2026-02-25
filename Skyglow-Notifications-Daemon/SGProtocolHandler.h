#ifndef SKYGLOW_SG_PROTOCOL_HANDLER_H
#define SKYGLOW_SG_PROTOCOL_HANDLER_H

#import <Foundation/Foundation.h>
#import <openssl/rsa.h>

// --- Wire Constants ---
#define SGP_MAGIC               ((uint8_t)0x53)
#define SGP_VERSION             ((uint8_t)0x02)
#define SGP_HEADER_SIZE         8
#define SGP_MAX_PAYLOAD_LEN     4096

// --- Timing (seconds) ---
#define SGP_PONG_TIMEOUT_SEC       15
#define SGP_CHALLENGE_WINDOW_SEC  300

// --- Fixed field lengths (bytes) ---
#define SGP_ROUTING_KEY_LEN     32
#define SGP_MSG_ID_LEN          16
#define SGP_NONCE_LEN           32
#define SGP_PING_SEQ_LEN         8
#define SGP_GCM_IV_LEN          12
#define SGP_GCM_TAG_LEN         16

// --- Return Codes for SGP_ProcessNextIncomingMessage ---
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
- (void)protocolDidReceiveNotification:(NSDictionary *)notificationData;
- (void)protocolDidReceiveWelcomeChallenge;
- (void)protocolDidAuthenticateSuccessfully;
- (void)protocolDidCompleteTokenRegistration:(NSString *)bundleIdentifier;
@optional
- (void)protocolDidFinishOfflineQueueDrain;
- (void)protocolDidCompleteRegistrationWithAddress:(NSString *)address 
                                        privateKey:(NSString *)pemKey 
                                     serverVersion:(uint32_t)version;
- (void)protocolDidFailRegistrationWithCode:(uint8_t)code reason:(NSString *)reason;
- (void)protocolDidReceiveKeepAlivePong;
- (void)protocolDidReceiveTimeSyncWithOffset:(int64_t)offsetSeconds;
@end

// --- Public C-API ---

void SGP_SetDelegate(id<SGProtocolDelegate> delegate);
BOOL SGP_IsConnected(void);
void SGP_AbortConnection(void);
int  SGP_ConnectToServer(const char *ip, int port, NSString *pinnedCert);
void SGP_DisconnectFromServer(void);
void SGP_SendClientDisconnect(void);
NSString *SGP_BeginFirstTimeRegistration(void);
void SGP_BeginLoginHandshake(NSString *address, RSA *privKey);
int  SGP_ProcessNextIncomingMessage(double pingIntervalSec);
BOOL SGP_RegisterDeviceToken(NSData *routingKey, NSString *bundleID);
void SGP_EnqueueAcknowledgement(NSData *msgID, int status);
void SGP_FlushPendingAcknowledgements(void);
void SGP_FlushActiveTopicFilter(void);
void SGP_RequestOfflineMessages(void);
uint32_t SGP_GetLastDisconnectRetryAfter(void);

#endif /* SKYGLOW_SG_PROTOCOL_HANDLER_H */