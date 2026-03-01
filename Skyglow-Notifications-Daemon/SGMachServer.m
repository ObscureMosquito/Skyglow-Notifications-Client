#import "SGMachServer.h"
#import "SGTokenManager.h"
#import "SGDatabaseManager.h"
#import "SGConfiguration.h"
#import "SGMachProtocol.h"
#include <bootstrap.h>
#include <string.h>

kern_return_t SGMach_SendPushToAppTopic(NSString *topic, NSDictionary *payload) {
    if (!topic || [topic length] == 0) return KERN_INVALID_ARGUMENT;
    
    NSData *plistData = nil;
    
    if (payload) {
        plistData = [NSPropertyListSerialization dataWithPropertyList:payload
                                                               format:NSPropertyListBinaryFormat_v1_0
                                                              options:0
                                                                error:NULL];
    }
    
    if (!plistData) plistData = [NSData data];

    mach_port_t bootstrapPort;
    task_get_bootstrap_port(mach_task_self(), &bootstrapPort);
    
    mach_port_t servicePort;
    kern_return_t kr = bootstrap_look_up(bootstrapPort, SKYGLOW_MACH_SERVICE_NAME_PUSH, &servicePort);
    if (kr != KERN_SUCCESS) return kr;

    if (plistData.length > SKYGLOW_MAX_USERINFO_SIZE) return KERN_RESOURCE_SHORTAGE;

    SGMachPushRequestMessage msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_remote_port = servicePort;
    msg.header.msgh_id = SG_MACH_MSG_REQUEST_PUSH;
    msg.type = SG_MACH_MSG_REQUEST_PUSH;

    strlcpy(msg.topic, [topic UTF8String], sizeof(msg.topic));
    msg.userInfoLength = (uint32_t)plistData.length;
    memcpy(msg.userInfoData, plistData.bytes, plistData.length);

    size_t size = offsetof(SGMachPushRequestMessage, userInfoData) + plistData.length;
    size = (size + 3) & ~3;
    msg.header.msgh_size = (mach_msg_size_t)size;

    kr = mach_msg(&msg.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, msg.header.msgh_size, 0, MACH_PORT_NULL, 500, MACH_PORT_NULL);
    
    mach_port_deallocate(mach_task_self(), servicePort);
    
    return kr;
}

@implementation SGMachServer {
    SGTokenManager *_tokenManager;
}

- (void)startMachBootstrapServices {
    _tokenManager = [[SGTokenManager alloc] init];
    mach_port_t serverPort;
    
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &serverPort);
    mach_port_insert_right(mach_task_self(), serverPort, serverPort, MACH_MSG_TYPE_MAKE_SEND);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    bootstrap_register(bootstrap_port, SKYGLOW_MACH_SERVICE_NAME_TOKEN, serverPort);
#pragma clang diagnostic pop

    NSLog(@"[SGMachServer] Listening for token requests on: %s", SKYGLOW_MACH_SERVICE_NAME_TOKEN);

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self runMessageLoopWithPort:serverPort];
    });
}

- (void)runMessageLoopWithPort:(mach_port_t)port {
    const size_t bufSize = sizeof(SGMachTokenRequestMessage) + 512;
    
    while (1) {
        @autoreleasepool {
            uint8_t buffer[bufSize];
            memset(buffer, 0, bufSize);
            
            SGMachRequestMessage *base = (SGMachRequestMessage *)buffer;
            kern_return_t kr = mach_msg(&base->header, MACH_RCV_MSG, 0, (mach_msg_size_t)bufSize, port, 0, MACH_PORT_NULL);

            if (kr != KERN_SUCCESS) continue;

            if (base->type == SG_MACH_MSG_REQUEST_TOKEN) {
                [self handleTokenRequest:(SGMachTokenRequestMessage *)buffer];
            } else if (base->type == SG_MACH_MSG_FEEDBACK_DATA) {
                [self handleFeedback:(SGMachFeedbackResponse *)buffer];
            }
        }
    }
}

- (void)handleTokenRequest:(SGMachTokenRequestMessage *)request {
    NSString *bundleID = [[NSString alloc] initWithBytes:request->bundleID 
                                                  length:strnlen(request->bundleID, 256) 
                                                encoding:NSUTF8StringEncoding];
    
    SGMachTokenResponseMessage response;
    memset(&response, 0, sizeof(response));
    response.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    response.header.msgh_size = sizeof(SGMachTokenResponseMessage);
    response.header.msgh_remote_port = request->header.msgh_remote_port;
    response.header.msgh_id = request->header.msgh_id + 100;

    NSData *token = nil;
    NSError *error = nil;
    
    if (![[SGConfiguration sharedConfiguration] isEnabled]) {
        error = [NSError errorWithDomain:@"com.skyglow.mach" code:503 userInfo:@{NSLocalizedDescriptionKey: @"Daemon is explicitly disabled in Settings"}];
    } else {
        token = [_tokenManager synchronizedTokenForBundleIdentifier:bundleID error:&error];
    }

    if (token) {
        response.type = SG_MACH_MSG_RESPONSE_TOKEN;
        response.tokenLength = (uint32_t)token.length;
        memcpy(response.tokenData, token.bytes, response.tokenLength);
    } else {
        response.type = SG_MACH_MSG_ERROR;
        const char *desc = error ? [[error localizedDescription] UTF8String] : NULL;
        strlcpy(response.error, desc ? desc : "Unknown Hardware Token Generator Error", sizeof(response.error));
    }

    mach_msg(&response.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, sizeof(response), 0, MACH_PORT_NULL, 500, MACH_PORT_NULL);
    [bundleID release];
}

- (void)handleFeedback:(SGMachFeedbackResponse *)feedback {
    NSString *topic = [[NSString alloc] initWithBytes:feedback->topic length:strnlen(feedback->topic, SKYGLOW_MAX_TOPIC_SIZE) encoding:NSUTF8StringEncoding];
    NSString *reason = [[NSString alloc] initWithBytes:feedback->reason length:strnlen(feedback->reason, SKYGLOW_MAX_REASON_SIZE) encoding:NSUTF8StringEncoding];
    
    [_tokenManager revokeTokenForBundleIdentifier:topic reason:reason];
    
    [topic release];
    [reason release];
}

@end