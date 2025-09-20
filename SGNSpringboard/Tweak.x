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

// Uninstall feedback trigger
%hook SBApplicationUninstallationOperation
-(void)main {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *bundleId = [self valueForKey:@"_bundleIdentifier"];
        NSLog(@"[SGN Springboard] App is being uninstalled! %@", bundleId);
        // Send bundleId to all clients
        if (bundleId) {
            NotifyAllClients([bundleId UTF8String]);
        }
    });
}
%end