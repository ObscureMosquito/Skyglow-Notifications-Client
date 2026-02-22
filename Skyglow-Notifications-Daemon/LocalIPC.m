#import "LocalIPC.h"
#include "Tokens.h"
#include "DBManager.h"
#include "TweakMachMessages.h"
#include <string.h>

kern_return_t LocalIPC_SendPush(NSString *topic, NSDictionary *userInfo) {
    if (!topic || [topic length] == 0) {
        NSLog(@"[LocalIPC] Missing topic");
        return KERN_INVALID_ARGUMENT;
    }

    NSData *topicData = [topic dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
    if (!topicData || topicData.length == 0) return KERN_INVALID_ARGUMENT;

    NSData *plistData = nil;
    if (userInfo) {
        NSError *err = nil;
        plistData = [NSPropertyListSerialization dataWithPropertyList:userInfo
                                                               format:NSPropertyListBinaryFormat_v1_0
                                                              options:0
                                                                error:&err];
        if (!plistData) return KERN_INVALID_ARGUMENT;
    } else {
        plistData = [NSData data];
    }

    mach_port_t bootstrapPort = MACH_PORT_NULL;
    kern_return_t kr = task_get_bootstrap_port(mach_task_self(), &bootstrapPort);
    if (kr != KERN_SUCCESS) return KERN_FAILURE;

    mach_port_t servicePort = MACH_PORT_NULL;
    kr = bootstrap_look_up(bootstrapPort, SKYGLOW_MACH_SERVICE_NAME_PUSH, &servicePort);
    if (kr != KERN_SUCCESS) return KERN_FAILURE;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winvalid-offsetof"
    const size_t maxInline = sizeof(((MachPushRequestMessage *)0)->userInfoData);
#pragma clang diagnostic pop

    if ((size_t)plistData.length > maxInline) return KERN_RESOURCE_SHORTAGE;

    MachPushRequestMessage msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_remote_port = servicePort;
    msg.header.msgh_id          = SKYGLOW_REQUEST_PUSH;
    msg.body.msgh_descriptor_count = 0;
    msg.type                    = SKYGLOW_REQUEST_PUSH;

    size_t maxTopic = sizeof(msg.topic) - 1;
    size_t copyLen  = MIN((size_t)topicData.length, maxTopic);
    memcpy(msg.topic, topicData.bytes, copyLen);
    msg.topic[copyLen] = '\0';

    msg.userInfoLength = (uint32_t)plistData.length;
    if (plistData.length > 0) {
        memcpy(msg.userInfoData, plistData.bytes, plistData.length);
    }

    size_t usedSize = offsetof(MachPushRequestMessage, userInfoData) + plistData.length;
    usedSize = (usedSize + 3) & ~(size_t)3;
    msg.header.msgh_size = (mach_msg_size_t)usedSize;

    kr = mach_msg(&msg.header, MACH_SEND_MSG, msg.header.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    return kr;
}

@implementation LocalIPC {
    Tokens *tokens;
}

- (void)startMachServer {
    kern_return_t kr;
    mach_port_t serverPort;

    self->tokens = [[Tokens alloc] init];

    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &serverPort);
    if (kr != KERN_SUCCESS) return;

    kr = mach_port_insert_right(mach_task_self(), serverPort, serverPort, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), serverPort);
        return;
    }

    kr = bootstrap_register(bootstrap_port, SKYGLOW_MACH_SERVICE_NAME_TOKEN, serverPort);
    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), serverPort);
        return;
    }

    NSLog(@"[LocalIPC] Registered mach service: %s", SKYGLOW_MACH_SERVICE_NAME_TOKEN);

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self handleMachMessages:serverPort];
    });
}

- (void)handleMachMessages:(mach_port_t)serverPort {
    // Buffer large enough for the biggest incoming message type
    const size_t bufSize = sizeof(MachFeedbackResponce) + 512;

    while (1) {
        @autoreleasepool {
            char receiveBuffer[bufSize];
            memset(receiveBuffer, 0, bufSize);

            MachTokenRequestMessage *request = (MachTokenRequestMessage *)receiveBuffer;
            request->header.msgh_local_port = serverPort;

            kern_return_t kr = mach_msg(&request->header,
                                        MACH_RCV_MSG, 0, (mach_msg_size_t)bufSize,
                                        serverPort, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);

            if (kr != KERN_SUCCESS) {
                NSLog(@"[MachMsgs] Receive error: %s (%d)", mach_error_string(kr), kr);
                if (kr == MACH_RCV_TOO_LARGE) {
                    // Drain the oversized message so we don't get stuck
                    mach_msg_header_t drain;
                    mach_msg(&drain, MACH_RCV_MSG | MACH_RCV_LARGE, 0, 0,
                             serverPort, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
                }
                continue;
            }

            if (request->type == SKYGLOW_REQUEST_TOKEN) {
                [self handleTokenRequest:request];
            } else if (request->type == SKYGLOW_FEEDBACK_DATA) {
                [self handleFeedback:(MachFeedbackResponce *)receiveBuffer];
            } else {
                NSLog(@"[MachMsgs] Unknown request type: %d", request->type);
            }
        }
    }
}

- (void)handleTokenRequest:(MachTokenRequestMessage *)request {
    // Validate bundle ID
    if (request->bundleID[0] == '\0') {
        NSLog(@"[MachMsgs] Token request with empty bundle ID");
        return;
    }

    // Must have a valid reply port
    if (request->header.msgh_remote_port == MACH_PORT_NULL) {
        NSLog(@"[MachMsgs] Token request missing reply port");
        return;
    }

    NSString *bundleID = [NSString stringWithUTF8String:request->bundleID];

    // Check if token already exists - if so, return the cached one.
    // This is the correct behavior: one active token per (device, bundle_id).
    NSArray *existing = [[DBManager sharedStorage] dataForBundleID:bundleID];
    if ([existing count] > 0) {
        NSLog(@"[MachMsgs] Token request for: %@ (returning cached token)", bundleID);
    } else {
        NSLog(@"[MachMsgs] Token request for: %@ (generating new token)", bundleID);
    }

    // Prepare response
    MachTokenResponseMessage response;
    memset(&response, 0, sizeof(response));

    // The client sent a MAKE_SEND_ONCE right as its reply port (msgh_local_port).
    // The kernel delivered it to us as msgh_remote_port (a send-once right).
    // We MUST use MOVE_SEND_ONCE to consume it — COPY_SEND would fail because
    // we only hold a send-once right, not a send right.
    // No MACH_MSGH_BITS_COMPLEX: we have no port/OOL descriptors in the body.
    response.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
    response.header.msgh_size        = sizeof(MachTokenResponseMessage);
    response.header.msgh_remote_port = request->header.msgh_remote_port;
    response.header.msgh_local_port  = MACH_PORT_NULL;
    response.header.msgh_id          = request->header.msgh_id + 100;
    response.body.msgh_descriptor_count = 0;

    NSError *error = nil;
    NSData *tokenData = [self->tokens getDeviceToken:bundleID error:&error];

    if (tokenData && [tokenData length] > 0) {
        response.type        = SKYGLOW_RESPONSE_TOKEN;
        response.tokenLength = (uint32_t)MIN([tokenData length], (NSUInteger)SKYGLOW_MAX_TOKEN_SIZE);
        memcpy(response.tokenData, [tokenData bytes], response.tokenLength);
        response.error[0] = '\0';
        NSLog(@"[MachMsgs] Generated token (%u bytes) for %@", response.tokenLength, bundleID);
    } else {
        response.type        = SKYGLOW_ERROR;
        response.tokenLength = 0;
        const char *errMsg = error ? [[error localizedDescription] UTF8String]
                                   : "Unknown error generating device token";
        strlcpy(response.error, errMsg, sizeof(response.error));
        NSLog(@"[MachMsgs] Token generation failed for %@: %s", bundleID, response.error);
    }

    kern_return_t kr = mach_msg(&response.header, MACH_SEND_MSG, sizeof(response), 0,
                                MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[MachMsgs] Send response error: %s (%d)", mach_error_string(kr), kr);
    }
}

- (void)handleFeedback:(MachFeedbackResponce *)feedback {
    NSString *topic  = [NSString stringWithUTF8String:feedback->topic];
    NSString *reason = [NSString stringWithUTF8String:feedback->reason];
    NSLog(@"[MachMsgs] Feedback for topic=%@, reason=%@", topic, reason);

    if (topic && [topic length] > 0) {
        [self->tokens removeDeviceTokenForBundleId:topic reason:reason];
    }
}

@end