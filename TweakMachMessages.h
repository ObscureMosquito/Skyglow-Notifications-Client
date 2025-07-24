#ifndef SKYGLOW_MACH_MESSAGES_H
#define SKYGLOW_MACH_MESSAGES_H

#import <Foundation/Foundation.h>
#import <mach/mach.h>

#define SKYGLOW_MACH_SERVICE_NAME "com.skyglow.snd.devicetoken"
#define SKYGLOW_MAX_TOKEN_SIZE 32

// Make sure structures are aligned properly for IPC
#pragma pack(4)

typedef enum {
    SKYGLOW_REQUEST_TOKEN = 1,
    SKYGLOW_RESPONSE_TOKEN = 2,
    SKYGLOW_ERROR = 3
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

#pragma pack()

#endif /* SKYGLOW_MACH_MESSAGES_H */