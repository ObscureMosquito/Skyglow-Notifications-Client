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

static void ShowTokenFailureAlert(NSString *bundleId) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *msg = [NSString stringWithFormat:
            @"Skyglow could not obtain a token for \"%@\". "
            @"Please try again.", bundleId];
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

    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &replyPort);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[SGN] RequestToken: port_allocate failed %d for %@", kr, bundleID);
        return nil;
    }
    mach_port_insert_right(mach_task_self(), replyPort, replyPort, MACH_MSG_TYPE_MAKE_SEND);

    kr = bootstrap_look_up(bootstrap_port, SKYGLOW_MACH_SERVICE_NAME_TOKEN, &daemonPort);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[SGN] RequestToken: bootstrap_look_up failed %d for %@", kr, bundleID);
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

    kr = mach_msg(&req.header, MACH_SEND_MSG, sizeof(req), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[SGN] RequestToken: send failed %d for %@", kr, bundleID);
        mach_port_deallocate(mach_task_self(), daemonPort);
        mach_port_deallocate(mach_task_self(), replyPort);
        return nil;
    }

    NSLog(@"[SGN] RequestToken: request sent for %@, waiting...", bundleID);

    // Use a union with generous padding to handle any struct size mismatch
    // between the tweak and daemon builds (different toolchains/alignment).
    union {
        SGMachTokenResponseMessage resp;
        uint8_t pad[512];
    } u;
    memset(&u, 0, sizeof(u));
    kr = mach_msg(&u.resp.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(u), replyPort, 5000, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[SGN] RequestToken: receive failed kr=%d (TIMED_OUT=%d, TOO_LARGE=%d) for %@",
              kr, MACH_RCV_TIMED_OUT, 0x10004004, bundleID);
    } else {
        NSLog(@"[SGN] RequestToken: response type=%d tokenLength=%u error='%s' for %@",
              u.resp.type, u.resp.tokenLength, u.resp.error, bundleID);
        if (u.resp.type == SG_MACH_MSG_RESPONSE_TOKEN && u.resp.tokenLength > 0 && u.resp.tokenLength <= SKYGLOW_MAX_TOKEN_SIZE) {
            result = [NSData dataWithBytes:u.resp.tokenData length:u.resp.tokenLength];
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

@interface SBRemoteApplication : NSObject
- (void)remoteNotificationRegistrationSucceededWithDeviceToken:(NSData *)deviceToken;
@end

@interface NSObject (SGNAppExtras)
- (NSString *)bundleIdentifier;
- (SBRemoteApplication *)remoteApplication;
@end

#pragma mark - Token Registration

// Forward declaration — SGN_InstallTokenGuard is defined in the Token Guard section below
static void SGN_InstallTokenGuard(void);

// Complete a push registration entirely within SpringBoard, delivering `token`
// to the app without involving APNs at all. The app receives the token via its
// normal -didRegisterForRemoteNotificationsWithDeviceToken: callback.
static void CompleteRegistrationWithSkyglowToken(id application, id environment, int notificationTypes, NSData *token) {
    NSString *bundleId = [application bundleIdentifier];
    if (!bundleId.length || !token) return;

    // Install the token guard now — SpringBoard is fully loaded at this point,
    // so all private classes are registered and objc_getClassList will find them.
    SGN_InstallTokenGuard();

    SBRemoteNotificationServer *server = [%c(SBRemoteNotificationServer) sharedInstance];

    // Get or create the SBRemoteNotificationClient
    NSMutableDictionary *clientsDict = [server valueForKey:@"_bundleIdentifiersToClients"];
    SBRemoteNotificationClient *client = clientsDict[bundleId];
    BOOL needsPersist = NO;
    if (!client) {
        client = [[%c(SBRemoteNotificationClient) alloc] initWithBundleIdentifier:bundleId];
        clientsDict[bundleId] = client;
        needsPersist = YES;
    }
    if (![[client environment] isEqual:environment]) {
        [client setEnvironment:environment];
        needsPersist = YES;
    }
    int requestedTypes = notificationTypes & 0xF;
    if ([client appEnabledTypes] != requestedTypes) {
        [client setAppEnabledTypes:requestedTypes];
        needsPersist = YES;
    }

    // Show the iOS permission alert (badges/sounds/alerts) if not yet presented
    int settingsPresentedTypes = [client settingsPresentedTypes];
    if (notificationTypes & ~settingsPresentedTypes & 0xF) {
        int alertTypes = (notificationTypes & 0x8) ? 0xF : 0x7;
        SBRemoteNotificationPermissionAlert *alert =
            [[%c(SBRemoteNotificationPermissionAlert) alloc] initWithApplication:application notificationTypes:alertTypes];
        if (alert) {
            SBAlertItemsController *ctrl = [%c(SBAlertItemsController) sharedInstance];
            [ctrl deactivateAlertItemsOfClass:[%c(SBRemoteNotificationPermissionAlert) class]];
            [ctrl activateAlertItem:alert];
            [client setSettingsPresentedTypes:settingsPresentedTypes | requestedTypes];
        }
    }

    if (needsPersist) {
        [[%c(SBApplicationPersistence) sharedInstance]
            setArchivedObject:client
                       forKey:@"SBRemoteNotificationClient"
    bundleOrDisplayIdentifier:bundleId];
        [server performSelector:@selector(calculateTopics)];
    }

    [client setLastKnownDeviceToken:token];

    // Deliver token to app — triggers -didRegisterForRemoteNotificationsWithDeviceToken:
    if ([application respondsToSelector:@selector(remoteApplication)]) {
        SBRemoteApplication *remoteApp = [application remoteApplication];
        if ([remoteApp respondsToSelector:@selector(remoteNotificationRegistrationSucceededWithDeviceToken:)]) {
            NSLog(@"[SGN] CompleteRegistration: delivering Skyglow token to %@", bundleId);
            [remoteApp remoteNotificationRegistrationSucceededWithDeviceToken:token];
        } else {
            NSLog(@"[SGN] CompleteRegistration: remoteApp missing selector for %@", bundleId);
        }
    } else {
        NSLog(@"[SGN] CompleteRegistration: no remoteApplication for %@", bundleId);
    }
}

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
        // ── "Use Skyglow" ──────────────────────────────────────────────
        NSMutableDictionary *prefs = [[NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath] mutableCopy] ?: [NSMutableDictionary dictionary];
        NSMutableDictionary *appStatus = [[prefs objectForKey:@"appStatus"] mutableCopy] ?: [NSMutableDictionary dictionary];
        [appStatus setObject:@YES forKey:sPendingBundleId];
        [prefs setObject:appStatus forKey:@"appStatus"];
        [prefs writeToFile:kPrefsPlistPath atomically:YES];
        [appStatus release];
        [prefs release];

        if (sPendingIsModern) {
            // iOS 9+: token delivery is handled by the result block path
            DeliverSkyglowToken(sPendingBundleId);
        } else {
            // iOS 6-8: complete registration entirely ourselves, no APNs involved
            NSData *token = RequestTokenFromDaemon(sPendingBundleId);
            if (token) {
                CompleteRegistrationWithSkyglowToken(sPendingApp, sPendingEnv, sPendingTypes, token);
            } else {
                NSLog(@"[SGN] Alert: failed to get token for %@", sPendingBundleId);
                ShowTokenFailureAlert(sPendingBundleId);
                // Undo the plist write so the alert re-appears next launch
                NSMutableDictionary *revertPrefs = [[NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath] mutableCopy] ?: [NSMutableDictionary dictionary];
                NSMutableDictionary *revertStatus = [[revertPrefs objectForKey:@"appStatus"] mutableCopy] ?: [NSMutableDictionary dictionary];
                [revertStatus removeObjectForKey:sPendingBundleId];
                [revertPrefs setObject:revertStatus forKey:@"appStatus"];
                [revertPrefs writeToFile:kPrefsPlistPath atomically:YES];
                [revertStatus release];
                [revertPrefs release];
            }
        }
    } else {
        // ── "Use Apple Push" ───────────────────────────────────────────
        // Remove key so alert re-appears next launch (don't permanently suppress)
        NSMutableDictionary *prefs = [[NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath] mutableCopy] ?: [NSMutableDictionary dictionary];
        NSMutableDictionary *appStatus = [[prefs objectForKey:@"appStatus"] mutableCopy] ?: [NSMutableDictionary dictionary];
        [appStatus removeObjectForKey:sPendingBundleId];
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

    NSString *bundleId = [application bundleIdentifier];
    NSLog(@"[SGN] Classic hook fired for %@", bundleId);

    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath];
    id existing = [[prefs objectForKey:@"appStatus"] objectForKey:bundleId];

    if (existing) {
        if ([existing boolValue]) {
            // Known Skyglow app — complete registration ourselves, never touch APNs
            NSData *token = RequestTokenFromDaemon(bundleId);
            if (token) {
                NSLog(@"[SGN] Classic hook: completing Skyglow registration for %@", bundleId);
                CompleteRegistrationWithSkyglowToken(application, environment, notificationTypes, token);
                return 1;
            }
            // Token fetch failed — log and deliver nothing. App won't get a token
            // this launch; it will retry on next launch via the hook.
            NSLog(@"[SGN] Classic hook: token fetch failed for %@, delivering nothing", bundleId);
            return 0;
        } else {
            // Opted for APNs
            NSLog(@"[SGN] Classic hook: APNs pass-through for %@", bundleId);
            return %orig;
        }
    }

    // First time — show choice alert, suppress APNs entirely
    NSLog(@"[SGN] Classic hook: showing choice alert for %@", bundleId);
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
        NSMutableDictionary *sndpPrefs = [[NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath] mutableCopy] ?: [NSMutableDictionary dictionary];
        NSMutableDictionary *appStatus = [[sndpPrefs objectForKey:@"appStatus"] mutableCopy] ?: [NSMutableDictionary dictionary];
        [appStatus removeObjectForKey:bundleId];
        [sndpPrefs setObject:appStatus forKey:@"appStatus"];
        [sndpPrefs writeToFile:kPrefsPlistPath atomically:YES];
        [appStatus release];
        [sndpPrefs release];
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            SendFeedbackToDaemon(bundleId, @"User removed from Skyglow");
        });
    }
}



// ── Skyglow Token Guard (runtime) ────────────────────────────────────────────
//
// We can't use a %hook with a class name because the internal SpringBoard class
// that delivers tokens to apps has a different name on each iOS version.
// Instead we discover it at runtime and hook it with MSHookMessageEx.
// This correctly intercepts ALL token deliveries for ALL apps on ALL iOS versions.

#import <substrate.h>

static BOOL SGN_IsSkyglowToken(NSData *token) {
    if (!token || token.length < 16) return NO;
    // Skyglow tokens: bytes 0-15 = server address UTF-8, zero-padded.
    // Server addresses are printable ASCII (e.g. "skyglow.es" = 0x73...).
    // APNs tokens are cryptographically random — first byte is essentially
    // never a printable ASCII character in practice.
    const uint8_t *b = (const uint8_t *)token.bytes;
    return (b[0] >= 0x20 && b[0] <= 0x7E);
}

static NSString *SGN_BundleIdForRemoteAppProxy(id proxy) {
    // Try common ivar names for the backing SBApplication across iOS versions
    for (NSString *ivarName in @[@"_application", @"_app", @"_sbApplication"]) {
        id sbApp = GetIvar(proxy, [ivarName UTF8String]);
        if (sbApp && [sbApp respondsToSelector:@selector(bundleIdentifier)]) {
            NSString *bid = [sbApp bundleIdentifier];
            if (bid.length) return bid;
        }
    }
    // Fallback: proxy itself may respond
    if ([proxy respondsToSelector:@selector(bundleIdentifier)]) {
        return [proxy bundleIdentifier];
    }
    return nil;
}

// Original IMP saved by MSHookMessageEx
static void (*SGN_Original_TokenDelivery)(id, SEL, NSData *) = NULL;

static void SGN_Hook_TokenDelivery(id self, SEL _cmd, NSData *token) {
    NSString *bundleId = SGN_BundleIdForRemoteAppProxy(self);

    if (bundleId.length) {
        NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath];
        id existing = [[prefs objectForKey:@"appStatus"] objectForKey:bundleId];
        if (existing && [existing boolValue]) {
            if (!SGN_IsSkyglowToken(token)) {
                NSLog(@"[SGN] TokenGuard: dropping non-Skyglow token for %@ (first byte=0x%02x)",
                      bundleId, token.length > 0 ? ((const uint8_t *)token.bytes)[0] : 0);
                return;
            }
            NSLog(@"[SGN] TokenGuard: accepting Skyglow token for %@", bundleId);
        }
    }

    if (SGN_Original_TokenDelivery) {
        SGN_Original_TokenDelivery(self, _cmd, token);
    }
}

static void SGN_InstallTokenGuard(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
    SEL sel = @selector(remoteNotificationRegistrationSucceededWithDeviceToken:);
    int classCount = objc_getClassList(NULL, 0);
    if (classCount <= 0) return;

    Class *classes = (Class *)malloc(sizeof(Class) * classCount);
    if (!classes) return;
    classCount = objc_getClassList(classes, classCount);

    for (int i = 0; i < classCount; i++) {
        // Only look at classes that directly implement this method (not inherited)
        Method m = class_getInstanceMethod(classes[i], sel);
        if (!m) continue;
        // Verify it's defined on this class, not a superclass
        if (class_getInstanceMethod(class_getSuperclass(classes[i]), sel) == m) continue;

        NSLog(@"[SGN] TokenGuard: hooking %s for token delivery interception",
              class_getName(classes[i]));
        MSHookMessageEx(classes[i], sel, (IMP)SGN_Hook_TokenDelivery,
                        (IMP *)&SGN_Original_TokenDelivery);
        // Only hook the first matching class — there should only be one
        break;
    }
    free(classes);
    }); // dispatch_once
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
