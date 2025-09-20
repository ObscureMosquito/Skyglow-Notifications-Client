#import <mach/mach.h>
#include <bootstrap.h>
#import "TweakMachMessages.h"
#import <objc/runtime.h>
#import <objc/message.h>

static mach_port_t gSkyglowPort = MACH_PORT_NULL;

@interface APSIncomingMessage : NSObject
+ (instancetype)initWithTopic:(id)arg1 userInfo:(id)arg2;
@end


@interface SBRemoteNotificationServer : NSObject
+ (instancetype)sharedInstance;
- (void)connection:(id)arg1 didReceiveIncomingMessage:(id)arg2;
@end


@interface SBApplicationUninstallationOperation : NSObject
{
    NSString *_bundleIdentifier;
}
@end


static void SendNotification(NSString *topic, NSDictionary *userInfo) {
    APSIncomingMessage *messageObj = [[%c(APSIncomingMessage) alloc] initWithTopic:topic userInfo:userInfo];
    [[%c(SBRemoteNotificationServer) sharedInstance] connection:nil didReceiveIncomingMessage:messageObj];
}



static void HandlePush(MachPushRequestMessage *req) {
	NSLog(@"[SGN Springboard] HandlePush");
    NSString *topic = [NSString stringWithUTF8String:req->topic] ?: @"";
    NSDictionary *userInfo = nil;
    if (req->userInfoLength > 0 && req->userInfoLength <= SKYGLOW_MAX_USERINFO_SIZE) {
        NSData *data = [NSData dataWithBytes:req->userInfoData length:req->userInfoLength];
        userInfo = [NSPropertyListSerialization propertyListWithData:data
                                                             options:NSPropertyListMutableContainersAndLeaves
                                                              format:NULL
                                                               error:NULL];
        if (![userInfo isKindOfClass:[NSDictionary class]]) {
            userInfo = nil;
        }
    }
    SendNotification(topic, userInfo ?: @{});
}

static void MachServerLoop() {
    while (1) {
        MachPushRequestMessage req;
        memset(&req, 0, sizeof(req));
        kern_return_t kr = mach_msg(&req.header,
                                    MACH_RCV_MSG,
                                    0,
                                    sizeof(req),
                                    gSkyglowPort,
                                    MACH_MSG_TIMEOUT_NONE,
                                    MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) continue;
        if (req.type == SKYGLOW_REQUEST_PUSH) {
            HandlePush(&req);
        }
    }
}

// Uninstall feedback trigger
%hook SBApplicationUninstallationOperation
-(void)main {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *bundleId = [self valueForKey:@"_bundleIdentifier"];
        NSLog(@"[SGN Springboard] App is being uninstalled! %@", bundleId);
        // Send bundleId to all clients
        if (bundleId) {
            // Convert topic to UTF8 once (fail if cannot be represented)
            NSData *topicData = [bundleId dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
            if (!topicData || topicData.length == 0) {
                NSLog(@"[SendFeedback] Topic UTF8 conversion failed");
                return;
            }

            NSString *reason = @"App uninstalled";
            NSData *reasonData = [reason dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];

            mach_port_t bootstrapPort = MACH_PORT_NULL;
            kern_return_t kr = task_get_bootstrap_port(mach_task_self(), &bootstrapPort);
            if (kr != KERN_SUCCESS || bootstrapPort == MACH_PORT_NULL) {
                NSLog(@"[SendFeedback] task_get_bootstrap_port: %s", mach_error_string(kr));
                return;
            }

            mach_port_t servicePort = MACH_PORT_NULL;
            kr = bootstrap_look_up(bootstrapPort, SKYGLOW_MACH_SERVICE_NAME_TOKEN, &servicePort);
            if (kr != KERN_SUCCESS || servicePort == MACH_PORT_NULL) {
                NSLog(@"[SendFeedback] bootstrap_look_up(%s): %s",
                    SKYGLOW_MACH_SERVICE_NAME_TOKEN, mach_error_string(kr));
                return;
            }

            MachFeedbackResponce msg;
            memset(&msg, 0, sizeof(msg));

            msg.header.msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
            msg.header.msgh_remote_port = servicePort;
            msg.header.msgh_id          = SKYGLOW_FEEDBACK_DATA;
            msg.body.msgh_descriptor_count = 0;
            msg.type = SKYGLOW_FEEDBACK_DATA;

            // topic
            size_t maxTopic = sizeof(msg.topic) - 1;
            size_t copyLen = MIN((size_t)topicData.length, maxTopic);
            memcpy(msg.topic, topicData.bytes, copyLen);
            msg.topic[copyLen] = '\0';
            if (copyLen < topicData.length) {
                NSLog(@"[SendFeedback] Feedback Topic truncated (%zu > %zu): %@",
                    (size_t)topicData.length, maxTopic, bundleId);
            }

            // reason i hope
            size_t maxReason = sizeof(msg.reason) - 1;
            copyLen = MIN((size_t)reasonData.length, maxReason);
            memcpy(msg.reason, reasonData.bytes, copyLen);
            msg.reason[copyLen] = '\0';
            if (copyLen < reasonData.length) {
                NSLog(@"[SendFeedback] Feedback Reason truncated (%zu > %zu): %@",
                    (size_t)reasonData.length, maxReason, reason);
            }

            size_t usedSize = sizeof(MachFeedbackResponce);
            // 4-byte align
            usedSize = (usedSize + 3) & ~(size_t)3;

            if (usedSize > sizeof(msg) || usedSize > UINT32_MAX) {
                NSLog(@"[SendFeedback] Internal size computation invalid (%zu)", usedSize);
                return;
            }
            msg.header.msgh_size = (mach_msg_size_t)usedSize;

            NSLog(@"[SendFeedback] topic='%@' totalMsgSize=%u",
                bundleId, msg.header.msgh_size);

            kr = mach_msg(&msg.header,
                        MACH_SEND_MSG,
                        msg.header.msgh_size,
                        0,
                        MACH_PORT_NULL,
                        MACH_MSG_TIMEOUT_NONE,
                        MACH_PORT_NULL);
            if (kr != KERN_SUCCESS) {
                NSLog(@"[SendFeedback] mach_msg send failed: %s (%d)",
                    mach_error_string(kr), kr);
            }
            return;
        }
    });
    %orig;
}
%end

%ctor {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &gSkyglowPort);
        if (kr != KERN_SUCCESS) return;
        kr = mach_port_insert_right(mach_task_self(), gSkyglowPort, gSkyglowPort, MACH_MSG_TYPE_MAKE_SEND);
        if (kr != KERN_SUCCESS) return;
        mach_port_t bootstrapPort = MACH_PORT_NULL;
        task_get_bootstrap_port(mach_task_self(), &bootstrapPort);
        bootstrap_register(bootstrapPort, SKYGLOW_MACH_SERVICE_NAME_PUSH, gSkyglowPort); // todo fix
        MachServerLoop();
    });
}
