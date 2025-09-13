#ifndef SKYGLOW_MACH_MESSAGES_H
#define SKYGLOW_MACH_MESSAGES_H

#import <Foundation/Foundation.h>
#import <mach/mach.h>

#define SKYGLOW_MACH_SERVICE_NAME_TOKEN "com.skyglow.sgn.token"
#define SKYGLOW_MACH_SERVICE_NAME_PUSH  "com.skyglow.sgn.push"
#define SKYGLOW_MAX_TOKEN_SIZE 32
#define SKYGLOW_MAX_TOPIC_SIZE 128
#define SKYGLOW_MAX_USERINFO_SIZE 1024

// Make sure structures are aligned properly for IPC
#pragma pack(4)

typedef enum {
    SKYGLOW_REQUEST_TOKEN = 1,
    SKYGLOW_RESPONSE_TOKEN = 2,
    SKYGLOW_ERROR = 3,
    SKYGLOW_REQUEST_PUSH = 4
} MachMessageType;

typedef struct {
    mach_msg_header_t header;
    // Add a body descriptor for complex messages
    mach_msg_body_t body;
    MachMessageType type;
    char bundleID[256];
    // Add padding to ensure proper alignment
    uint8_t padding[4];
} MachRequestMessage;

typedef struct {
    mach_msg_header_t header;
    // Add a body descriptor for complex messages
    mach_msg_body_t body;
    MachMessageType type;
    uint32_t tokenLength;
    char tokenData[SKYGLOW_MAX_TOKEN_SIZE];
    char error[256];
    // Add padding to ensure proper alignment
    uint8_t padding[4];
} MachResponseMessage;

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t   body;
    MachMessageType   type;              // SKYGLOW_REQUEST_PUSH
    uint32_t userInfoLength;             // bytes actually used
    char topic[SKYGLOW_MAX_TOPIC_SIZE];
    char userInfoData[SKYGLOW_MAX_USERINFO_SIZE]; // serialized plist (binary)
} MachPushRequestMessage;

#pragma pack()

#endif /* SKYGLOW_MACH_MESSAGES_H */