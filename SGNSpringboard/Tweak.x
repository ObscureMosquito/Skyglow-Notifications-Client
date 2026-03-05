/*
 * Tweak.x — Skyglow Notifications SpringBoard Hook
 *
 * 1. Run a Mach server to receive push messages from the daemon.
 * 2. Intercept remote-notification registration to route through Skyglow.
 * 3. Send uninstall feedback to the daemon when apps are removed.
 *
 * iOS Version Support:
 *   Notification Delivery: iOS 3–9 (versioned paths)
 *   Registration Hook:     iOS 3–8 (SBRemoteNotificationServer)
 *                          iOS 9   (UNNotificationRegistrarConnectionListener)
 *   Uninstall Hook:        iOS 3–7 (SBApplicationUninstallationOperation)
 *                          iOS 8–9 (SBApplicationController -uninstallApplication:)
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <bootstrap.h>
#import "../Skyglow-Notifications-Daemon/SGMachProtocol.h"

#pragma mark - Private Class Interfaces

@interface APSIncomingMessage : NSObject
- (instancetype)initWithTopic:(NSString *)topic userInfo:(NSDictionary *)userInfo;
- (void)setTimestamp:(NSDate *)date;
@end

@interface SBApplicationController : NSObject
+ (instancetype)sharedInstance;
- (id)applicationWithDisplayIdentifier:(NSString *)displayIdentifier;
- (id)applicationWithBundleIdentifier:(NSString *)bundleIdentifier;
- (void)uninstallApplication:(id)application;
@end

@interface SBRemoteNotificationServer : NSObject
+ (instancetype)sharedInstance;
- (int)registerApplication:(id)application forEnvironment:(NSString *)environment withTypes:(int)types;
@end

@interface UNNotificationRegistrarConnectionListener : NSObject
- (void)requestTokenForRemoteNotificationsForBundleIdentifier:(NSString *)bundleIdentifier withResult:(id)resultBlock;
@end

static NSString *const kPrefsPlistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
static mach_port_t gPushReceiverPort = MACH_PORT_NULL;

#pragma mark - Utility Helpers

static id GetIvar(id obj, const char *name) {
    if (!obj || !name) return nil;
    Ivar iv = class_getInstanceVariable(object_getClass(obj), name);
    return iv ? object_getIvar(obj, iv) : nil;
}

static id SBApp_LookupByIdentifier(NSString *bundleId) {
    SBApplicationController *ctrl = [%c(SBApplicationController) sharedInstance];
    if ([ctrl respondsToSelector:@selector(applicationWithBundleIdentifier:)]) {
        return [ctrl applicationWithBundleIdentifier:bundleId];
    }
    return [ctrl applicationWithDisplayIdentifier:bundleId];
}

static void EnsureAppInPlist(NSString *bundleId) {
    if (!bundleId.length) return;
    NSMutableDictionary *prefs = [[NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath] mutableCopy] ?: [NSMutableDictionary dictionary];
    NSMutableDictionary *appStatus = [[prefs objectForKey:@"appStatus"] mutableCopy] ?: [NSMutableDictionary dictionary];
    if ([appStatus objectForKey:bundleId] != nil) { [appStatus release]; [prefs release]; return; }
    [appStatus setObject:@YES forKey:bundleId];
    [prefs setObject:appStatus forKey:@"appStatus"];
    [prefs writeToFile:kPrefsPlistPath atomically:YES];
    [appStatus release];
    [prefs release];
}

static BOOL ShouldUseSkyglowForApp(NSString *bundleId) {
    if (!bundleId.length) return NO;
    EnsureAppInPlist(bundleId);
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath];
    NSDictionary *appStatus = [prefs objectForKey:@"appStatus"];
    return [[appStatus objectForKey:bundleId] boolValue];
}

/**
 * Lightweight probe: check if the daemon's Mach service is registered.
 * Does NOT send a message — only checks bootstrap namespace.
 */
static BOOL IsDaemonReachable(void) {
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, SKYGLOW_MACH_SERVICE_NAME_TOKEN, &port);
    if (kr == KERN_SUCCESS && port != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), port);
        return YES;
    }
    return NO;
}

static void ShowDaemonOfflineAlert(NSString *bundleId) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *msg = [NSString stringWithFormat:
            @"Skyglow cannot register \"%@\" for notifications because the daemon is not running. "
            @"Please enable Skyglow in Settings and try again.", bundleId];
        id alert = [[NSClassFromString(@"UIAlertView") alloc]
            initWithTitle:@"Skyglow" message:msg delegate:nil
            cancelButtonTitle:@"OK" otherButtonTitles:nil];
        [alert show];
        [alert release];
    });
}

#pragma mark - Mach IPC: Token & Feedback

static NSData *RequestTokenFromDaemon(NSString *bundleID) {
    if (!bundleID.length) return nil;

    mach_port_t replyPort = MACH_PORT_NULL;
    mach_port_t daemonPort = MACH_PORT_NULL;
    NSData *result = nil;

    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &replyPort) != KERN_SUCCESS) return nil;
    mach_port_insert_right(mach_task_self(), replyPort, replyPort, MACH_MSG_TYPE_MAKE_SEND);

    if (bootstrap_look_up(bootstrap_port, SKYGLOW_MACH_SERVICE_NAME_TOKEN, &daemonPort) != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), replyPort);
        return nil;
    }

    SGMachTokenRequestMessage req;
    memset(&req, 0, sizeof(req));
    req.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND);
    req.header.msgh_size = sizeof(req);
    req.header.msgh_remote_port = daemonPort;
    req.header.msgh_local_port = replyPort;
    req.header.msgh_id = SG_MACH_MSG_REQUEST_TOKEN;
    req.type = SG_MACH_MSG_REQUEST_TOKEN;
    strlcpy(req.bundleID, [bundleID UTF8String], sizeof(req.bundleID));

    if (mach_msg(&req.header, MACH_SEND_MSG, sizeof(req), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) == KERN_SUCCESS) {
        SGMachTokenResponseMessage resp;
        memset(&resp, 0, sizeof(resp));
        if (mach_msg(&resp.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(resp), replyPort, 5000, MACH_PORT_NULL) == KERN_SUCCESS) {
            if (resp.type == SG_MACH_MSG_RESPONSE_TOKEN && resp.tokenLength <= SKYGLOW_MAX_TOKEN_SIZE) {
                result = [NSData dataWithBytes:resp.tokenData length:resp.tokenLength];
            }
        }
    }

    mach_port_deallocate(mach_task_self(), daemonPort);
    mach_port_deallocate(mach_task_self(), replyPort);
    return result;
}

static void SendFeedbackToDaemon(NSString *bundleId, NSString *reason) {
    if (!bundleId.length) return;
    mach_port_t daemonPort = MACH_PORT_NULL;
    if (bootstrap_look_up(bootstrap_port, SKYGLOW_MACH_SERVICE_NAME_TOKEN, &daemonPort) != KERN_SUCCESS) return;

    SGMachFeedbackResponse msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_size = sizeof(msg);
    msg.header.msgh_remote_port = daemonPort;
    msg.header.msgh_id = SG_MACH_MSG_FEEDBACK_DATA;
    msg.type = SG_MACH_MSG_FEEDBACK_DATA;

    strlcpy(msg.topic, [bundleId UTF8String], sizeof(msg.topic));
    strlcpy(msg.reason, [reason UTF8String] ?: "uninstalled", sizeof(msg.reason));

    mach_msg(&msg.header, MACH_SEND_MSG, sizeof(msg), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    mach_port_deallocate(mach_task_self(), daemonPort);
}

/**
 * Shared token delivery logic: requests a token from the daemon and delivers
 * it back to the app via its remoteApplication proxy.
 */
static void DeliverSkyglowToken(NSString *bundleId) {
    NSString *safeBundleId = [bundleId copy];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSData *token = RequestTokenFromDaemon(safeBundleId);
        if (!token || [token length] == 0) {
            NSLog(@"[SGN] Token request failed for %@ — daemon may not be running", safeBundleId);
            dispatch_async(dispatch_get_main_queue(), ^{
                NSString *msg = [NSString stringWithFormat:
                    @"Skyglow: Failed to register %@. The notification daemon may not be running.",
                    safeBundleId];
                if (NSClassFromString(@"UILocalNotification")) {
                    UILocalNotification *note = [[NSClassFromString(@"UILocalNotification") alloc] init];
                    [note setAlertBody:msg];
                    [note setSoundName:@"UILocalNotificationDefaultSoundName"];
                    [[UIApplication sharedApplication] presentLocalNotificationNow:note];
                    [note release];
                } else {
                    id alert = [[NSClassFromString(@"UIAlertView") alloc]
                        initWithTitle:@"Skyglow" message:msg delegate:nil
                        cancelButtonTitle:@"OK" otherButtonTitles:nil];
                    [alert show];
                    [alert release];
                }
            });
            [safeBundleId release];
            return;
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                id freshApp = SBApp_LookupByIdentifier(safeBundleId);
                if (freshApp && [freshApp respondsToSelector:@selector(remoteApplication)]) {
                    id remoteApp = [freshApp performSelector:@selector(remoteApplication)];
                    if (remoteApp && [remoteApp respondsToSelector:@selector(remoteNotificationRegistrationSucceededWithDeviceToken:)]) {
                        [remoteApp performSelector:@selector(remoteNotificationRegistrationSucceededWithDeviceToken:) withObject:token];
                    }
                }
            } @catch (NSException *e) {
                NSLog(@"[SGN] Exception delivering token to %@: %@", safeBundleId, e);
            }
            [safeBundleId release];
        });
    });
}

#pragma mark - Notification Delivery

static NSDictionary *WrapInAPNSFormat(NSDictionary *flat) {
    NSMutableDictionary *alert = [NSMutableDictionary dictionary];
    if (flat[@"title"]) [alert setObject:flat[@"title"] forKey:@"title"];
    if (flat[@"body"])  [alert setObject:flat[@"body"]  forKey:@"body"];

    NSMutableDictionary *aps = [NSMutableDictionary dictionary];
    if (alert.count > 0) [aps setObject:alert forKey:@"alert"];
    if (flat[@"sound"])   [aps setObject:flat[@"sound"] forKey:@"sound"];

    NSMutableDictionary *result = [NSMutableDictionary dictionaryWithObject:aps forKey:@"aps"];
    if (flat[@"custom_data"]) [result setObject:flat[@"custom_data"] forKey:@"custom_data"];
    return result;
}

static void DeliverNotification(NSString *topic, NSDictionary *userInfo) {
    if (!topic.length) return;
    NSDictionary *apnsPayload = WrapInAPNSFormat(userInfo ?: @{});

    double cfVersion = kCFCoreFoundationVersionNumber;

    @try {
        if (cfVersion < 700.0) {
            id server = [NSClassFromString(@"SBRemoteNotificationServer") performSelector:@selector(sharedInstance)];
            if (server) {
                SEL sel = @selector(connection:didReceiveMessageForTopic:userInfo:);
                void (*send)(id, SEL, id, id, id) = (void *)objc_msgSend;
                send(server, sel, nil, topic, apnsPayload);
            }
        } else if (cfVersion < 1200.0) {
            APSIncomingMessage *msg = [[NSClassFromString(@"APSIncomingMessage") alloc] initWithTopic:topic userInfo:apnsPayload];
            [[NSClassFromString(@"SBRemoteNotificationServer") performSelector:@selector(sharedInstance)]
                performSelector:@selector(connection:didReceiveIncomingMessage:) withObject:nil withObject:msg];
            [msg release];
        } else {
            APSIncomingMessage *msg = [[NSClassFromString(@"APSIncomingMessage") alloc] initWithTopic:topic userInfo:apnsPayload];
            id userNS = [NSClassFromString(@"UNUserNotificationServer") performSelector:@selector(sharedInstance)];
            id registrar = GetIvar(userNS, "_registrarConnectionListener");
            id remoteSrv = GetIvar(registrar, "_remoteNotificationServer") ?: GetIvar(registrar, "_removeNotificationServer");
            if ([remoteSrv respondsToSelector:@selector(connection:didReceiveIncomingMessage:)]) {
                [remoteSrv performSelector:@selector(connection:didReceiveIncomingMessage:) withObject:nil withObject:msg];
            }
            [msg release];
        }
    } @catch (NSException *e) {
        NSLog(@"[SGN] Failed to inject push notification: %@", e);
    }
}

#pragma mark - Push Receiver Mach Loop

static void PushReceiverLoop(void) {
    while (1) {
        @autoreleasepool {
            SGMachPushRequestMessage req;
            memset(&req, 0, sizeof(req));

            kern_return_t kr = mach_msg(&req.header, MACH_RCV_MSG, 0, sizeof(req), gPushReceiverPort, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
            if (kr == KERN_SUCCESS && req.type == SG_MACH_MSG_REQUEST_PUSH) {
                NSString *topic = [NSString stringWithUTF8String:req.topic];
                NSDictionary *userInfo = nil;
                if (req.userInfoLength > 0 && req.userInfoLength <= SKYGLOW_MAX_USERINFO_SIZE) {
                    NSData *data = [NSData dataWithBytes:req.userInfoData length:req.userInfoLength];
                    userInfo = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:NULL];
                }
                NSLog(@"[SGN] Delivering push for topic: %@", topic);
                DeliverNotification(topic, userInfo);
            }
        }
    }
}

static BOOL StartPushReceiver(void) {
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &gPushReceiverPort) != KERN_SUCCESS) return NO;
    if (mach_port_insert_right(mach_task_self(), gPushReceiverPort, gPushReceiverPort, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) return NO;

    mach_port_t bsPort = MACH_PORT_NULL;
    task_get_bootstrap_port(mach_task_self(), &bsPort);
    if (bootstrap_register(bsPort, SKYGLOW_MACH_SERVICE_NAME_PUSH, gPushReceiverPort) != KERN_SUCCESS) return NO;
    return YES;
}

#pragma mark - Uninstall Detection

%group HookUninstall_Classic
%hook SBApplicationUninstallationOperation
- (void)main {
    NSString *bundleId = [(id)self valueForKey:@"_bundleIdentifier"];
    if (bundleId.length) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            SendFeedbackToDaemon(bundleId, @"App uninstalled");
        });
    }
    %orig;
}
%end
%end

%group HookUninstall_Modern
%hook SBApplicationController
- (void)uninstallApplication:(id)application {
    NSString *bundleId = nil;
    if ([application respondsToSelector:@selector(bundleIdentifier)]) {
        bundleId = [application performSelector:@selector(bundleIdentifier)];
    }
    if (bundleId.length) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            SendFeedbackToDaemon(bundleId, @"App uninstalled");
        });
    }
    %orig;
}
%end
%end

#pragma mark - Token Registration

static id sPendingServer      = nil;
static id sPendingApp         = nil;
static id sPendingEnv         = nil;
static int sPendingTypes      = 0;
static NSString *sPendingBundleId = nil;
static id sPendingResultBlock = nil;
static BOOL sPendingIsModern  = NO;
static BOOL sPassThrough      = NO;

@interface SGRegistrationAlertDelegate : NSObject
@end

@implementation SGRegistrationAlertDelegate

- (void)alertView:(id)alertView clickedButtonAtIndex:(NSInteger)buttonIndex {
    if (buttonIndex == 1) {
        if (!IsDaemonReachable()) {
            ShowDaemonOfflineAlert(sPendingBundleId);
        } else {
            NSMutableDictionary *prefs = [[NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath] mutableCopy] ?: [NSMutableDictionary dictionary];
            NSMutableDictionary *appStatus = [[prefs objectForKey:@"appStatus"] mutableCopy] ?: [NSMutableDictionary dictionary];
            [appStatus setObject:@YES forKey:sPendingBundleId];
            [prefs setObject:appStatus forKey:@"appStatus"];
            [prefs writeToFile:kPrefsPlistPath atomically:YES];
            [appStatus release];
            [prefs release];

            if (sPendingIsModern) {
                sPassThrough = YES;
                [sPendingServer requestTokenForRemoteNotificationsForBundleIdentifier:sPendingBundleId withResult:sPendingResultBlock];
            } else {
                sPassThrough = YES;
                [(SBRemoteNotificationServer *)sPendingServer registerApplication:sPendingApp forEnvironment:sPendingEnv withTypes:sPendingTypes];
            }
            DeliverSkyglowToken(sPendingBundleId);
        }
    } else {
        NSMutableDictionary *prefs = [[NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath] mutableCopy] ?: [NSMutableDictionary dictionary];
        NSMutableDictionary *appStatus = [[prefs objectForKey:@"appStatus"] mutableCopy] ?: [NSMutableDictionary dictionary];
        [appStatus setObject:@NO forKey:sPendingBundleId];
        [prefs setObject:appStatus forKey:@"appStatus"];
        [prefs writeToFile:kPrefsPlistPath atomically:YES];
        [appStatus release];
        [prefs release];

        if (sPendingIsModern) {
            sPassThrough = YES;
            [sPendingServer requestTokenForRemoteNotificationsForBundleIdentifier:sPendingBundleId withResult:sPendingResultBlock];
        } else {
            sPassThrough = YES;
            [(SBRemoteNotificationServer *)sPendingServer registerApplication:sPendingApp forEnvironment:sPendingEnv withTypes:sPendingTypes];
        }
    }

    [sPendingServer release];      sPendingServer = nil;
    [sPendingApp release];         sPendingApp = nil;
    [sPendingEnv release];         sPendingEnv = nil;
    [sPendingBundleId release];    sPendingBundleId = nil;
    [sPendingResultBlock release]; sPendingResultBlock = nil;
    sPendingTypes = 0;
    sPendingIsModern = NO;
}
@end

static SGRegistrationAlertDelegate *sAlertDelegate = nil;

static void ShowRegistrationChoiceAlert(NSString *bundleId) {
    if (!sAlertDelegate) sAlertDelegate = [[SGRegistrationAlertDelegate alloc] init];

    NSString *msg = [NSString stringWithFormat:
        @"\"%@\" wants to receive push notifications. "
        @"Would you like to route them through Skyglow, or use standard Apple Push?",
        bundleId];
    id alert = [[NSClassFromString(@"UIAlertView") alloc]
        initWithTitle:@"Skyglow Notifications"
              message:msg
             delegate:sAlertDelegate
    cancelButtonTitle:@"Use Apple Push"
    otherButtonTitles:@"Use Skyglow", nil];
    [alert show];
    [alert release];
}

%group HookRegistration_Classic
%hook SBRemoteNotificationServer
- (int)registerApplication:(id)application forEnvironment:(id)environment withTypes:(int)notificationTypes {
    if (sPassThrough) {
        sPassThrough = NO;
        return %orig;
    }

    NSString *bundleId = [application performSelector:@selector(bundleIdentifier)];

    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath];
    NSDictionary *appStatus = [prefs objectForKey:@"appStatus"];
    id existing = [appStatus objectForKey:bundleId];
    if (existing) {
        if ([existing boolValue]) {
            DeliverSkyglowToken(bundleId);
        }
        return %orig;
    }

    [sPendingServer release];   sPendingServer = [self retain];
    [sPendingApp release];      sPendingApp = [application retain];
    [sPendingEnv release];      sPendingEnv = [environment retain];
    [sPendingBundleId release]; sPendingBundleId = [bundleId copy];
    sPendingTypes = notificationTypes;
    sPendingIsModern = NO;

    ShowRegistrationChoiceAlert(bundleId);
    return 0;
}
%end
%end

%group HookRegistration_iOS9
%hook UNNotificationRegistrarConnectionListener
- (void)requestTokenForRemoteNotificationsForBundleIdentifier:(NSString *)bundleIdentifier withResult:(id)resultBlock {
    if (sPassThrough) {
        sPassThrough = NO;
        %orig;
        return;
    }

    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath];
    NSDictionary *appStatus = [prefs objectForKey:@"appStatus"];
    id existing = [appStatus objectForKey:bundleIdentifier];
    if (existing) {
        if ([existing boolValue]) {
            DeliverSkyglowToken(bundleIdentifier);
        }
        %orig;
        return;
    }

    [sPendingServer release];      sPendingServer = [self retain];
    [sPendingBundleId release];    sPendingBundleId = [bundleIdentifier copy];
    [sPendingResultBlock release]; sPendingResultBlock = [resultBlock copy];
    sPendingIsModern = YES;

    ShowRegistrationChoiceAlert(bundleIdentifier);
}
%end
%end

#pragma mark - Settings Integration

static void handleSettingsAppRegistration(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    CFPreferencesAppSynchronize(CFSTR("com.skyglow.sndp"));
    NSDictionary *prefs = [[NSUserDefaults standardUserDefaults] persistentDomainForName:@"com.skyglow.sndp"];
    NSString *bundleId = [prefs objectForKey:@"lastRegisteredApp"];

    if (bundleId.length) {
        if (kCFCoreFoundationVersionNumber < 1200.0) {
            id app = SBApp_LookupByIdentifier(bundleId);
            SBRemoteNotificationServer *server = [%c(SBRemoteNotificationServer) sharedInstance];
            if (app && server) {
                [server registerApplication:app forEnvironment:@"production" withTypes:7];
            }
        } else {
            DeliverSkyglowToken(bundleId);
        }
    }
}

static void handleSettingsAppUnregistration(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    CFPreferencesAppSynchronize(CFSTR("com.skyglow.sndp"));
    NSDictionary *prefs = [[NSUserDefaults standardUserDefaults] persistentDomainForName:@"com.skyglow.sndp"];
    NSString *bundleId = [prefs objectForKey:@"lastUnregisteredApp"];
    if (bundleId.length) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            SendFeedbackToDaemon(bundleId, @"User removed from Skyglow");
        });
    }
}

#pragma mark - Constructor

%ctor {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        if (StartPushReceiver()) PushReceiverLoop();
    });

    if (kCFCoreFoundationVersionNumber < 1140.0) {
        %init(HookUninstall_Classic);
    } else {
        %init(HookUninstall_Modern);
    }

    if (kCFCoreFoundationVersionNumber < 1200.0) {
        %init(HookRegistration_Classic);
    } else {
        %init(HookRegistration_iOS9);
    }

    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL, handleSettingsAppRegistration, CFSTR("com.skyglow.sgn.registerInputApp"), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL, handleSettingsAppUnregistration, CFSTR("com.skyglow.sgn.unregisterInputApp"), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
}
