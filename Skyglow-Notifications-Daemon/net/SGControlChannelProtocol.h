#ifndef SKYGLOW_SG_CONTROL_CHANNEL_PROTOCOL_H
#define SKYGLOW_SG_CONTROL_CHANNEL_PROTOCOL_H

#import <Foundation/Foundation.h>
#import <mach/mach.h>

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

#define SKYGLOW_CONTROL_SERVICE_DAEMON       "com.skyglow.sgn.control.daemon"
#define SKYGLOW_CONTROL_SERVICE_SPRINGBOARD  "com.skyglow.sgn.control.springboard"
#define SG_CONTROL_MAGIC                     ((uint8_t)0x43)
#define SG_CONTROL_VERSION                   ((uint8_t)0x01)
#define SG_CONTROL_MAX_PAYLOAD               4096
#define SG_CONTROL_MAX_TOKEN_SIZE            48
#define SG_CONTROL_MAX_BUNDLE_ID_SIZE        256
#define SG_CONTROL_MAX_REASON_SIZE           64
#define SG_CONTROL_MAX_USERINFO_SIZE         3072
#define SG_CONTROL_MAX_ERROR_DETAIL_SIZE     256
#define SG_CONTROL_MAX_EVENT_DATA_SIZE       1024
#define SG_CONTROL_MAX_SERVER_ADDRESS_SIZE   256
#define SG_CONTROL_MAX_PROFILE_PEM_SIZE      3584
#define SG_CONTROL_DEFAULT_REQUEST_TIMEOUT_SEC  5.0
#define SG_CONTROL_DELETE_APP_TIMEOUT_SEC       12.0
#define SG_CONTROL_SEND_TIMEOUT_MS              1000

typedef enum : uint8_t {
    SGCMSG_TOKEN_REQUEST       = 0x10,  /* SGCTokenRequestPayload */
    SGCMSG_RELOAD_CONFIG       = 0x13,  /* (empty) */
    SGCMSG_TEST_INJECT         = 0x14,  /* (empty) */
    SGCMSG_PUSH_DELIVERY       = 0x16,  /* SGCPushDeliveryPayload */
    SGCMSG_SUBSCRIBE           = 0x17,  /* SGCSubscribePayload */
    SGCMSG_UNSUBSCRIBE         = 0x18,  /* SGCUnsubscribePayload */
    SGCMSG_REGISTER_INPUT_APP  = 0x19,  /* SGCBundleIdPayload — debug-only */
    SGCMSG_UNREGISTER_INPUT_APP= 0x1A,  /* DEPRECATED; opcode reserved */
    SGCMSG_ENABLE_APP          = 0x1B,  /* SGCBundleIdPayload */
    SGCMSG_DISABLE_APP         = 0x1C,  /* SGCBundleIdPayload */
    SGCMSG_DELETE_APP          = 0x1D,  /* SGCBundleIdPayload */
    SGCMSG_RESET_APP_REGISTRATION    = 0x1E,  /* SGCBundleIdPayload */
    SGCMSG_LIST_PUSH_REGISTERED_APPS = 0x1F,  /* (empty) -> SGCMSG_BUNDLE_ID_LIST */
    SGCMSG_QUERY_STATUS        = 0x20,  /* (empty) -> SGCMSG_STATUS_RESPONSE */
    SGCMSG_DELETE_PROFILE      = 0x21,  /* SGCProfileIndexPayload */
    SGCMSG_SAVE_PROFILE        = 0x22,  /* SGCProfileSavePayload */
    SGCMSG_SET_ACTIVE_PROFILE  = 0x23,  /* SGCProfileIndexPayload */
    SGCMSG_SET_ENABLED         = 0x24,  /* SGCEnabledPayload */
    SGCMSG_CLEAR_APP_INTENT    = 0x25,  /* SGCBundleIdPayload */

    SGCMSG_GENERIC_ACK         = 0x30,  /* (empty) */
    SGCMSG_TOKEN_RESPONSE      = 0x31,  /* SGCTokenResponsePayload */
    SGCMSG_ERROR_RESPONSE      = 0x32,  /* SGCErrorResponsePayload */
    SGCMSG_BUNDLE_ID_LIST      = 0x33,  /* SGCBundleIdListPayload */
    SGCMSG_STATUS_RESPONSE     = 0x34,  /* SGStatusPayload */

    SGCMSG_EVENT_DELIVERY      = 0x40,  /* SGCEventDeliveryPayload */
} SGControlMessageType;

typedef enum : uint16_t {
    SGCEVT_STATE_CHANGED      = 1,  /* SGStatusPayload */
} SGControlEventType;

/* DAEMON_DISABLED and UNSUPPORTED are terminal; every other code is retryable. */
typedef enum : uint16_t {
    SGCERR_OK                = 0,
    SGCERR_DAEMON_DISABLED   = 1,
    SGCERR_UNREACHABLE       = 2,
    SGCERR_TIMEOUT           = 3,
    SGCERR_INVALID_REQUEST   = 4,
    SGCERR_UNAUTHORIZED      = 5,
    SGCERR_INTERNAL          = 6,
    SGCERR_DAEMON_BUSY       = 7,
    SGCERR_NOT_FOUND         = 8,
    SGCERR_UNSUPPORTED       = 9,
} SGControlError;

#pragma pack(4)

typedef struct {
    mach_msg_header_t mach_header;
    mach_msg_body_t   mach_body;

    uint8_t  magic;            /* SG_CONTROL_MAGIC */
    uint8_t  version;          /* SG_CONTROL_VERSION */
    uint8_t  flags;            /* reserved in v1, must be 0 */
    uint8_t  messageType;      /* SGControlMessageType */

    uint16_t eventType;        /* only set on EVENT_DELIVERY */
    uint16_t errorCode;        /* only set on ERROR_RESPONSE */

    uint64_t requestId;        /* echoed in the matching response; 0 on events */
    uint64_t subscriptionId;   /* SUBSCRIBE/UNSUBSCRIBE/EVENT_DELIVERY; 0 otherwise */

    uint32_t payloadLength;    /* bytes used in payload[] */
    uint8_t  payload[SG_CONTROL_MAX_PAYLOAD];
} SGControlChannelMessage;

typedef struct {
    char bundleID[SG_CONTROL_MAX_BUNDLE_ID_SIZE];
} SGCTokenRequestPayload;

typedef struct {
    uint32_t tokenLength;
    uint8_t  tokenData[SG_CONTROL_MAX_TOKEN_SIZE];
} SGCTokenResponsePayload;

typedef struct {
    char     bundleID[SG_CONTROL_MAX_BUNDLE_ID_SIZE];
    uint32_t userInfoLength;
    uint8_t  userInfoData[SG_CONTROL_MAX_USERINFO_SIZE];
} SGCPushDeliveryPayload;

typedef struct {
    uint16_t eventType;
} SGCSubscribePayload;

typedef struct {
    uint64_t subscriptionId;
} SGCUnsubscribePayload;

typedef struct {
    char bundleID[SG_CONTROL_MAX_BUNDLE_ID_SIZE];
} SGCBundleIdPayload;

/* profileIndex is 1..5; out of range is rejected as SGCERR_INVALID_REQUEST. */
typedef struct {
    uint8_t profileIndex;
} SGCProfileIndexPayload;

typedef struct {
    uint8_t enabled;
} SGCEnabledPayload;

/* certificatePEMLength 0 keeps the profile's existing certificate. */
typedef struct {
    uint8_t  profileIndex;
    uint8_t  reserved;
    uint16_t certificatePEMLength;
    char     serverAddress[SG_CONTROL_MAX_SERVER_ADDRESS_SIZE];
    uint8_t  certificatePEM[SG_CONTROL_MAX_PROFILE_PEM_SIZE];
} SGCProfileSavePayload;

/* Packed, variable-length: uint16 count, then per entry uint16 len + UTF-8 bytes
 * (NOT null-terminated). Iterate strictly by the encoded lengths. */
typedef struct {
    uint16_t count;
    uint8_t  data[];
} SGCBundleIdListPayload;

typedef struct {
    uint16_t eventType;
    uint32_t dataLength;
    uint8_t  data[SG_CONTROL_MAX_EVENT_DATA_SIZE];
} SGCEventDeliveryPayload;

typedef struct {
    char message[SG_CONTROL_MAX_ERROR_DETAIL_SIZE];
} SGCErrorResponsePayload;

#pragma pack()

#endif
