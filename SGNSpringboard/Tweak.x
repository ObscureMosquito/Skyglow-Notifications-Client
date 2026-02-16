#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <mach/mach.h>
#include <bootstrap.h>
#import "TweakMachMessages.h"
#import <objc/runtime.h>
#import <objc/message.h>
#import <UIKit/UIKit.h>

static mach_port_t gSkyglowPort = MACH_PORT_NULL;
static NSData *requestDeviceTokenFromDaemon(NSString *bundleID);

// ---- Forward declarations (no jailbreak headers needed) ----
@class UIApplication;
@class SBRemoteApplication;
@class APSIncomingMessage;

// ---- Private interfaces (minimal, just what we call) ----
@interface APSIncomingMessage : NSObject
- (instancetype)initWithTopic:(id)topic userInfo:(id)userInfo;
- (void)setTimestamp:(id)date; // used on iOS 10 in some implementations
@end

@interface SBRemoteNotificationServer : NSObject
+ (instancetype)sharedInstance;
// iOS 6-8 style
- (void)connection:(id)arg1 didReceiveIncomingMessage:(id)arg2;
// pre-iOS6 legacy (kept for completeness; won’t be used if you only support iOS6+)
- (void)connection:(id)arg1 didReceiveMessageForTopic:(id)topic userInfo:(id)userInfo;
@end

// iOS 9-ish
@interface UNUserNotificationServer : NSObject
+ (instancetype)sharedInstance;
@end

@interface UNNotificationRegistrarConnectionListener : NSObject
@end

@interface UNRemoteNotificationServer : NSObject
- (void)connection:(id)arg1 didReceiveIncomingMessage:(id)arg2;
@end

// iOS 10-ish
@interface UNSUserNotificationServer : NSObject
+ (instancetype)sharedInstance;
@end

@interface UNSRemoteNotificationServer : NSObject
- (void)connection:(id)arg1 didReceiveIncomingMessage:(id)arg2;
@end

@interface SBApplicationUninstallationOperation : NSObject
{
    NSString *_bundleIdentifier;
}
@end

@interface SBRemoteApplication : NSObject
- (void)remoteNotificationRegistrationSucceededWithDeviceToken:(NSData *)deviceToken;
@end

@interface UIApplication (Private)
- (BOOL)isSystemApplication;
- (BOOL)isInternalApplication;
- (NSString *)bundleIdentifier;
- (SBRemoteApplication *)remoteApplication;
@end

@interface SBRemoteNotificationClient : NSObject
- (instancetype)initWithBundleIdentifier:(NSString *)bundleIdentifier;
- (void)setEnvironment:(id)environment;
- (id)environment;
- (int)appEnabledTypes;
- (void)setAppEnabledTypes:(int)types;
- (int)settingsPresentedTypes;
- (void)setSettingsPresentedTypes:(int)types;
- (void)setLastKnownDeviceToken:(NSData *)token;
@end

@interface SBApplicationPersistence : NSObject
+ (instancetype)sharedInstance;
- (void)setArchivedObject:(id)object forKey:(NSString *)key bundleOrDisplayIdentifier:(NSString *)identifier;
@end

@interface SBRemoteNotificationPermissionAlert : NSObject
- (instancetype)initWithApplication:(id)application notificationTypes:(int)types;
@end

@interface SBAlertItemsController : NSObject
+ (instancetype)sharedInstance;
- (void)deactivateAlertItemsOfClass:(Class)alertClass;
- (void)activateAlertItem:(id)alert;
@end

// ---- Runtime ivar helper (no MSHookIvar needed) ----
static id GetIvarObject(id obj, const char *name) {
    if (!obj || !name) return nil;
    Ivar iv = class_getInstanceVariable(object_getClass(obj), name);
    if (!iv) return nil;
    return object_getIvar(obj, iv);
}

static void SendNotification(NSString *topic, NSDictionary *userInfo) {
    if (!topic.length) return;
    if (!userInfo) userInfo = @{};

    Class APSCls = objc_getClass("APSIncomingMessage");
    id messageObj = nil;
    if (APSCls && [APSCls instancesRespondToSelector:@selector(initWithTopic:userInfo:)]) {
        messageObj = [[APSCls alloc] initWithTopic:topic userInfo:userInfo];
    }

    // iOS 6–10 routing (same thresholds you showed before)
    double cf = kCFCoreFoundationVersionNumber;

    if (cf < 700.0) {
        // pre iOS 6 (kept for completeness)
        id srv = [objc_getClass("SBRemoteNotificationServer") sharedInstance];
        if (srv && [srv respondsToSelector:@selector(connection:didReceiveMessageForTopic:userInfo:)]) {
            [srv connection:nil didReceiveMessageForTopic:topic userInfo:userInfo];
        }
    } else if (cf < 1200.0) {
        // iOS 6/7/8
        id srv = [objc_getClass("SBRemoteNotificationServer") sharedInstance];
        if (srv && messageObj && [srv respondsToSelector:@selector(connection:didReceiveIncomingMessage:)]) {
            [srv connection:nil didReceiveIncomingMessage:messageObj];
        }
    } else if (cf < 1300.0) {
        // iOS 9
        id userNotificationServer = [objc_getClass("UNUserNotificationServer") sharedInstance];
        id registrar = GetIvarObject(userNotificationServer, "_registrarConnectionListener");
        id remoteSrv = GetIvarObject(registrar, "_remoteNotificationServer"); // some builds use this spelling

        // If that ivar name differs, try the common typo you had in your snippet
        if (!remoteSrv) remoteSrv = GetIvarObject(registrar, "_removeNotificationServer");

        if (remoteSrv && messageObj && [remoteSrv respondsToSelector:@selector(connection:didReceiveIncomingMessage:)]) {
            [remoteSrv connection:nil didReceiveIncomingMessage:messageObj];
        }
    } else {
        // iOS 10
        id userNotificationServer = [objc_getClass("UNSUserNotificationServer") sharedInstance];
        id remoteSrv = GetIvarObject(userNotificationServer, "_remoteNotificationService");

        if (messageObj && [messageObj respondsToSelector:@selector(setTimestamp:)]) {
            [messageObj setTimestamp:[NSDate date]];
        }

        if (remoteSrv && messageObj && [remoteSrv respondsToSelector:@selector(connection:didReceiveIncomingMessage:)]) {
            [remoteSrv connection:nil didReceiveIncomingMessage:messageObj];
        }
    }
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
        if (![userInfo isKindOfClass:[NSDictionary class]]) userInfo = nil;
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
- (void)main {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *bundleId = [self valueForKey:@"_bundleIdentifier"];
        NSLog(@"[SGN Springboard] App is being uninstalled! %@", bundleId);
        if (!bundleId) return;

        NSData *topicData = [bundleId dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
        if (!topicData.length) {
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

        size_t maxTopic = sizeof(msg.topic) - 1;
        size_t copyLen = MIN((size_t)topicData.length, maxTopic);
        memcpy(msg.topic, topicData.bytes, copyLen);
        msg.topic[copyLen] = '\0';

        size_t maxReason = sizeof(msg.reason) - 1;
        copyLen = MIN((size_t)reasonData.length, maxReason);
        memcpy(msg.reason, reasonData.bytes, copyLen);
        msg.reason[copyLen] = '\0';

        size_t usedSize = sizeof(MachFeedbackResponce);
        usedSize = (usedSize + 3) & ~(size_t)3;

        msg.header.msgh_size = (mach_msg_size_t)usedSize;

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
    });

    %orig;
}
%end


// 0 = apns
// 1 = skyglow
static int isUsingAPNSOrSkyglow(NSString *bundleId) {
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
    NSMutableDictionary *prefs = [[NSDictionary dictionaryWithContentsOfFile:plistPath] mutableCopy];
    if (!prefs) {
        NSLog(@"[SGN Springboard] Something has gone VERY wrong (sndp plist missing!)");
        return 0;
    }

    id existingAppStatus = prefs[@"appStatus"];
    NSMutableDictionary *appStatus = nil;
    if ([existingAppStatus isKindOfClass:[NSDictionary class]]) {
        appStatus = [existingAppStatus mutableCopy];
    } else {
        appStatus = [NSMutableDictionary dictionary];
    }

    if (appStatus[bundleId] == nil) {
        appStatus[bundleId] = @YES;
        prefs[@"appStatus"] = appStatus;
        [prefs writeToFile:plistPath atomically:YES];
    }

    return prefs[@"appStatus"][bundleId] ? 1 : 0;
}

%hook SBRemoteNotificationServer

- (int)registerApplication:(id)application forEnvironment:(id)environment withTypes:(int)notificationTypes {
    NSLog(@"[SGN Springboard] registerApplication:%@ forEnvironment:%@ withTypes:%d",
          [application bundleIdentifier], environment, notificationTypes);

    BOOL needsUpdate = NO;

    NSString *bundleIdentifier = [application bundleIdentifier];

    NSMutableDictionary *bundleIdentifiersToClients = [self valueForKey:@"_bundleIdentifiersToClients"];
    SBRemoteNotificationClient *client = [bundleIdentifiersToClients objectForKey:bundleIdentifier];

    if (client == nil) {
        client = [[%c(SBRemoteNotificationClient) alloc] initWithBundleIdentifier:bundleIdentifier];
        [bundleIdentifiersToClients setObject:client forKey:bundleIdentifier];
        needsUpdate = YES;
        NSLog(@"[SGN Springboard] Created new notification client for %@", bundleIdentifier);
    }

    if (![[client environment] isEqual:environment]) {
        [client setEnvironment:environment];
        needsUpdate = YES;
    }

    int appEnabledTypes = [client appEnabledTypes];
    int requestedTypes = notificationTypes & 0xF;
    if (appEnabledTypes != requestedTypes) {
        [client setAppEnabledTypes:requestedTypes];
        needsUpdate = YES;
    }

    NSMutableDictionary *environmentsToConnections = [self valueForKey:@"_environmentsToConnections"];
    id connection = [environmentsToConnections objectForKey:environment];

    if (connection == nil) {
        [self performSelector:@selector(calculateTopics)];
        connection = [environmentsToConnections objectForKey:environment];
    }

    id validConnection = nil;
    BOOL hasIdentity = NO;
    if (connection && [connection respondsToSelector:@selector(hasIdentity)]) {
        hasIdentity = ((intptr_t)[connection performSelector:@selector(hasIdentity)]) != 0;
    }
    if (hasIdentity) {
        validConnection = connection;
    }

    int settingsPresentedTypes = [client settingsPresentedTypes];

    if ((notificationTypes & 0x8) != 0 && (settingsPresentedTypes & 0x8) == 0) {
        int alertTypes = (requestedTypes != 0x8) ? 0xF : 0x8;
        SBRemoteNotificationPermissionAlert *alert =
            [[%c(SBRemoteNotificationPermissionAlert) alloc] initWithApplication:application notificationTypes:alertTypes];
        if (alert != nil) {
            SBAlertItemsController *alertController = [%c(SBAlertItemsController) sharedInstance];
            [alertController deactivateAlertItemsOfClass:[%c(SBRemoteNotificationPermissionAlert) class]];
            [alertController activateAlertItem:alert];
            [client setSettingsPresentedTypes:settingsPresentedTypes | requestedTypes];
        }
    } else if ((notificationTypes & ~settingsPresentedTypes & 0x7) != 0) {
        SBRemoteNotificationPermissionAlert *alert =
            [[%c(SBRemoteNotificationPermissionAlert) alloc] initWithApplication:application notificationTypes:0x7];
        if (alert != nil) {
            SBAlertItemsController *alertController = [%c(SBAlertItemsController) sharedInstance];
            [alertController deactivateAlertItemsOfClass:[%c(SBRemoteNotificationPermissionAlert) class]];
            [alertController activateAlertItem:alert];
            [client setSettingsPresentedTypes:settingsPresentedTypes | requestedTypes];
        }
    }

    NSData *publicToken = nil;
    if (isUsingAPNSOrSkyglow(bundleIdentifier) == 1) {
        publicToken = requestDeviceTokenFromDaemon(bundleIdentifier);
    } else {
        if (validConnection != nil) {
            publicToken = [validConnection performSelector:@selector(publicToken)];
        }
    }

    if (publicToken != nil) {
        NSLog(@"[SGN Springboard] Providing token to %@", bundleIdentifier);

        // ✅ Fix: cast so the compiler knows about remoteApplication
        if ([application respondsToSelector:@selector(remoteApplication)]) {
            SBRemoteApplication *remoteApp = [(UIApplication *)application remoteApplication];
            if ([remoteApp respondsToSelector:@selector(remoteNotificationRegistrationSucceededWithDeviceToken:)]) {
                [remoteApp remoteNotificationRegistrationSucceededWithDeviceToken:publicToken];
            }
        }

        [client setLastKnownDeviceToken:publicToken];
    } else {
        NSLog(@"[SGN Springboard] No token available for %@", bundleIdentifier);
    }

    if (needsUpdate) {
        [[%c(SBApplicationPersistence) sharedInstance]
            setArchivedObject:client
                       forKey:@"SBRemoteNotificationClient"
    bundleOrDisplayIdentifier:bundleIdentifier];
        [self performSelector:@selector(calculateTopics)];
    }

    return needsUpdate;
}

static NSData *requestDeviceTokenFromDaemon(NSString *bundleID) {
    if (![bundleID isKindOfClass:[NSString class]] || bundleID.length == 0) {
        return nil;
    }

    mach_port_t clientPort = MACH_PORT_NULL;
    mach_port_t serverPort = MACH_PORT_NULL;
    kern_return_t kr = KERN_SUCCESS;

    // Allocate receive right for reply port
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &clientPort);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[Skyglow Springboard] mach_port_allocate: %s", mach_error_string(kr));
        return nil;
    }

    // Add a send right so server can reply
    kr = mach_port_insert_right(mach_task_self(), clientPort, clientPort, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[Skyglow Springboard] mach_port_insert_right: %s", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), clientPort);
        return nil;
    }

    // Look up daemon service
    kr = bootstrap_look_up(bootstrap_port, SKYGLOW_MACH_SERVICE_NAME_TOKEN, &serverPort);
    if (kr != KERN_SUCCESS || serverPort == MACH_PORT_NULL) {
        NSLog(@"[Skyglow Springboard] bootstrap_look_up(%s): %s",
              SKYGLOW_MACH_SERVICE_NAME_TOKEN, mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), clientPort);
        return nil;
    }

    // Build request
    MachTokenRequestMessage request;
    memset(&request, 0, sizeof(request));

    request.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND);
    request.header.msgh_size = (mach_msg_size_t)sizeof(request);
    request.header.msgh_remote_port = serverPort;
    request.header.msgh_local_port  = clientPort;
    request.header.msgh_id = 100;

    request.body.msgh_descriptor_count = 0;
    request.type = SKYGLOW_REQUEST_TOKEN;

    const char *bundleIDStr = [bundleID UTF8String];
    if (!bundleIDStr) bundleIDStr = "";
    strncpy(request.bundleID, bundleIDStr, sizeof(request.bundleID) - 1);
    request.bundleID[sizeof(request.bundleID) - 1] = '\0';

    // Send
    kr = mach_msg(&request.header,
                  MACH_SEND_MSG,
                  request.header.msgh_size,
                  0,
                  MACH_PORT_NULL,
                  MACH_MSG_TIMEOUT_NONE,
                  MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[Skyglow Springboard] mach_msg send: %s", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), serverPort);
        mach_port_deallocate(mach_task_self(), clientPort);
        return nil;
    }

    // Receive response
    union {
        MachTokenResponseMessage resp;
        uint8_t pad[sizeof(MachTokenResponseMessage) + 512];
    } u;
    memset(&u, 0, sizeof(u));

    mach_msg_timeout_t timeout = 20000; // 20s
    kr = mach_msg(&u.resp.header,
                  MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                  0,
                  (mach_msg_size_t)sizeof(u),
                  clientPort,
                  timeout,
                  MACH_PORT_NULL);

    // Cleanup ports
    mach_port_deallocate(mach_task_self(), serverPort);
    mach_port_deallocate(mach_task_self(), clientPort);

    if (kr != KERN_SUCCESS) {
        NSLog(@"[Skyglow Springboard] mach_msg recv: %s (%d)", mach_error_string(kr), kr);
        return nil;
    }

    if (u.resp.type == SKYGLOW_RESPONSE_TOKEN && u.resp.tokenLength > 0) {
        if (u.resp.tokenLength > sizeof(u.resp.tokenData)) {
            NSLog(@"[Skyglow Springboard] tokenLength too large: %u", u.resp.tokenLength);
            return nil;
        }
        return [NSData dataWithBytes:u.resp.tokenData length:u.resp.tokenLength];
    }

    NSLog(@"[Skyglow Springboard] Token error: %s", u.resp.error);
    return nil;
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

        bootstrap_register(bootstrapPort, SKYGLOW_MACH_SERVICE_NAME_PUSH, gSkyglowPort);
        MachServerLoop();
        NSLog(@"AAAAAAAAAAAASASSAETATSDYRASDUYASDFAUITSFUIASFIAUYSFIAUSYFSA");
    });
}