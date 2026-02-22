#ifndef SKYGLOW_SG_MACH_PROTOCOL_H
#define SKYGLOW_SG_MACH_PROTOCOL_H

#import <Foundation/Foundation.h>
#import <mach/mach.h>

#define SKYGLOW_MACH_SERVICE_NAME_TOKEN "com.skyglow.sgn.token"
#define SKYGLOW_MACH_SERVICE_NAME_PUSH  "com.skyglow.sgn.push"

#define SKYGLOW_MAX_TOKEN_SIZE 48
#define SKYGLOW_MAX_TOPIC_SIZE 128
#define SKYGLOW_MAX_REASON_SIZE 64
#define SKYGLOW_MAX_USERINFO_SIZE 1024

#pragma pack(4)

typedef enum {
    SG_MACH_MSG_REQUEST_TOKEN  = 1,
    SG_MACH_MSG_RESPONSE_TOKEN = 2,
    SG_MACH_MSG_ERROR          = 3,
    SG_MACH_MSG_REQUEST_PUSH   = 4,
    SG_MACH_MSG_FEEDBACK_DATA  = 5,
} SGMachMessageType;

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    SGMachMessageType type;
} SGMachRequestMessage;

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    SGMachMessageType type;
    char bundleID[256];
    uint8_t padding[4];
} SGMachTokenRequestMessage;

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    SGMachMessageType type;
    uint32_t tokenLength;
    char tokenData[SKYGLOW_MAX_TOKEN_SIZE];
    char error[256];
    uint8_t padding[4];
} SGMachTokenResponseMessage;

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t   body;
    SGMachMessageType   type;
    uint32_t userInfoLength;
    char topic[SKYGLOW_MAX_TOPIC_SIZE];
    char userInfoData[SKYGLOW_MAX_USERINFO_SIZE];
} SGMachPushRequestMessage;

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    SGMachMessageType type;
    char topic[SKYGLOW_MAX_TOPIC_SIZE];
    char reason[SKYGLOW_MAX_REASON_SIZE];
} SGMachFeedbackResponse;

#pragma pack()

#endif /* SKYGLOW_SG_MACH_PROTOCOL_H */