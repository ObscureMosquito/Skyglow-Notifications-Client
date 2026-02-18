/*
 * Tweak.xm — Skyglow Notifications SpringBoard Hook
 *
 * Responsibilities:
 *   1. Run a Mach server to receive push messages from the daemon
 *      and deliver them to the system notification infrastructure.
 *   2. Intercept remote-notification registration so apps can be
 *      routed through Skyglow instead of APNS.
 *   3. Send uninstall feedback to the daemon when apps are removed.
 *   4. (Debug) Auto-register com.apple.Preferences on boot.
 */

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <bootstrap.h>
#import "TweakMachMessages.h"

// ═══════════════════════════════════════════════
#pragma mark - Constants & Globals
// ═══════════════════════════════════════════════

static NSString *const kPrefsPlistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";

/// The Mach port we own for receiving push delivery messages from the daemon.
static mach_port_t gPushReceiverPort = MACH_PORT_NULL;

// ═══════════════════════════════════════════════
#pragma mark - Private Class Interfaces
// ═══════════════════════════════════════════════

@class SBRemoteApplication;

@interface APSIncomingMessage : NSObject
- (instancetype)initWithTopic:(id)topic userInfo:(id)userInfo;
- (void)setTimestamp:(id)date;
@end

@interface SBRemoteNotificationServer : NSObject
+ (instancetype)sharedInstance;
- (void)connection:(id)conn didReceiveIncomingMessage:(id)msg;
- (void)connection:(id)conn didReceiveMessageForTopic:(id)topic userInfo:(id)info;
@end

@interface UNUserNotificationServer : NSObject
+ (instancetype)sharedInstance;
@end

@interface UNSUserNotificationServer : NSObject
+ (instancetype)sharedInstance;
@end

@interface SBRemoteApplication : NSObject
- (void)remoteNotificationRegistrationSucceededWithDeviceToken:(NSData *)token;
@end

@interface UIApplication (Private)
- (NSString *)bundleIdentifier;
- (SBRemoteApplication *)remoteApplication;
@end

@interface SBRemoteNotificationClient : NSObject
- (instancetype)initWithBundleIdentifier:(NSString *)bundleIdentifier;
- (void)setEnvironment:(id)env;
- (id)environment;
- (int)appEnabledTypes;
- (void)setAppEnabledTypes:(int)types;
- (int)settingsPresentedTypes;
- (void)setSettingsPresentedTypes:(int)types;
- (void)setLastKnownDeviceToken:(NSData *)token;
@end

@interface SBApplicationPersistence : NSObject
+ (instancetype)sharedInstance;
- (void)setArchivedObject:(id)obj forKey:(NSString *)key bundleOrDisplayIdentifier:(NSString *)ident;
@end

@interface SBRemoteNotificationPermissionAlert : NSObject
- (instancetype)initWithApplication:(id)app notificationTypes:(int)types;
@end

@interface SBAlertItemsController : NSObject
+ (instancetype)sharedInstance;
- (void)deactivateAlertItemsOfClass:(Class)cls;
- (void)activateAlertItem:(id)item;
@end

// ═══════════════════════════════════════════════
#pragma mark - Utility Helpers
// ═══════════════════════════════════════════════

/// Safe ivar access without MSHookIvar.
static id GetIvar(id obj, const char *name) {
    if (!obj || !name) return nil;
    Ivar iv = class_getInstanceVariable(object_getClass(obj), name);
    return iv ? object_getIvar(obj, iv) : nil;
}

/// Read the appStatus dictionary from the prefs plist.
static NSDictionary *ReadAppStatus(void) {
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath];
    id status = [prefs objectForKey:@"appStatus"];
    return [status isKindOfClass:[NSDictionary class]] ? status : @{};
}

/// Ensure a bundle ID exists in the appStatus plist.
/// If new, defaults to @YES (Skyglow enabled).
/// This is the ONLY function that mutates appStatus.
static void EnsureAppInPlist(NSString *bundleId) {
    if (!bundleId.length) return;

    NSDictionary *appStatus = ReadAppStatus();
    if ([appStatus objectForKey:bundleId] != nil) return; // already present

    NSMutableDictionary *prefs = [[NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath] mutableCopy]
                                  ?: [NSMutableDictionary dictionary];
    NSMutableDictionary *newStatus = [[prefs objectForKey:@"appStatus"] mutableCopy]
                                      ?: [NSMutableDictionary dictionary];
    [newStatus setObject:@YES forKey:bundleId];
    [prefs setObject:newStatus forKey:@"appStatus"];
    [prefs writeToFile:kPrefsPlistPath atomically:YES];

    NSLog(@"[SGN] Registered %@ in appStatus (defaulting to Skyglow)", bundleId);
}

/// Check whether a given app should use Skyglow (YES) or APNS (NO).
/// Also ensures the app is recorded in appStatus on first encounter.
static BOOL ShouldUseSkyglowForApp(NSString *bundleId) {
    if (!bundleId.length) return NO;

    // Ensure it's registered (writes @YES on first encounter)
    EnsureAppInPlist(bundleId);

    // Now read the actual value — must use boolValue, not truthiness!
    // (@NO is non-nil, so a bare nil-check would always return YES)
    NSDictionary *appStatus = ReadAppStatus();
    return [[appStatus objectForKey:bundleId] boolValue];
}

// ═══════════════════════════════════════════════
#pragma mark - Mach IPC: Token Request
// ═══════════════════════════════════════════════

/// Request a device token from the Skyglow daemon via Mach IPC.
/// Returns nil on failure. Thread-safe.
static NSData *RequestTokenFromDaemon(NSString *bundleID) {
    if (!bundleID.length) return nil;

    mach_port_t replyPort  = MACH_PORT_NULL;
    mach_port_t daemonPort = MACH_PORT_NULL;
    kern_return_t kr;
    NSData *result = nil;

    // Allocate a reply port
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &replyPort);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[SGN] Reply port alloc failed: %s", mach_error_string(kr));
        return nil;
    }
    kr = mach_port_insert_right(mach_task_self(), replyPort, replyPort, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[SGN] Reply port send right failed: %s", mach_error_string(kr));
        goto cleanup;
    }

    // Look up daemon
    kr = bootstrap_look_up(bootstrap_port, SKYGLOW_MACH_SERVICE_NAME_TOKEN, &daemonPort);
    if (kr != KERN_SUCCESS || daemonPort == MACH_PORT_NULL) {
        NSLog(@"[SGN] Daemon lookup failed: %s", mach_error_string(kr));
        goto cleanup;
    }

    // Build & send request
    {
        MachTokenRequestMessage req;
        memset(&req, 0, sizeof(req));

        req.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND);
        req.header.msgh_size        = (mach_msg_size_t)sizeof(req);
        req.header.msgh_remote_port = daemonPort;
        req.header.msgh_local_port  = replyPort;
        req.header.msgh_id          = 100;
        req.body.msgh_descriptor_count = 0;
        req.type = SKYGLOW_REQUEST_TOKEN;

        strlcpy(req.bundleID, [bundleID UTF8String] ?: "", sizeof(req.bundleID));

        kr = mach_msg(&req.header, MACH_SEND_MSG, sizeof(req), 0,
                      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            NSLog(@"[SGN] Token request send failed: %s", mach_error_string(kr));
            goto cleanup;
        }
    }

    // Receive response (20s timeout)
    {
        union {
            MachTokenResponseMessage resp;
            uint8_t pad[sizeof(MachTokenResponseMessage) + 512];
        } buf;
        memset(&buf, 0, sizeof(buf));

        kr = mach_msg(&buf.resp.header,
                      MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                      0, (mach_msg_size_t)sizeof(buf),
                      replyPort, 20000, MACH_PORT_NULL);

        if (kr != KERN_SUCCESS) {
            NSLog(@"[SGN] Token response recv failed: %s", mach_error_string(kr));
            goto cleanup;
        }

        if (buf.resp.type == SKYGLOW_RESPONSE_TOKEN &&
            buf.resp.tokenLength > 0 &&
            buf.resp.tokenLength <= sizeof(buf.resp.tokenData)) {
            result = [NSData dataWithBytes:buf.resp.tokenData length:buf.resp.tokenLength];
        } else {
            NSLog(@"[SGN] Token error for %@: %s", bundleID, buf.resp.error);
        }
    }

cleanup:
    if (daemonPort != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), daemonPort);
    if (replyPort  != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), replyPort);
    return result;
}

// ═══════════════════════════════════════════════
#pragma mark - Mach IPC: Feedback (Uninstall)
// ═══════════════════════════════════════════════

/// Notify the daemon that a bundle should be unregistered.
static void SendFeedbackToDaemon(NSString *bundleId, NSString *reason) {
    if (!bundleId.length) return;
    if (!reason) reason = @"unknown";

    mach_port_t daemonPort = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, SKYGLOW_MACH_SERVICE_NAME_TOKEN, &daemonPort);
    if (kr != KERN_SUCCESS || daemonPort == MACH_PORT_NULL) {
        NSLog(@"[SGN] Feedback: daemon lookup failed: %s", mach_error_string(kr));
        return;
    }

    MachFeedbackResponce msg;
    memset(&msg, 0, sizeof(msg));

    msg.header.msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_size        = (mach_msg_size_t)((sizeof(msg) + 3) & ~3u);
    msg.header.msgh_remote_port = daemonPort;
    msg.header.msgh_id          = SKYGLOW_FEEDBACK_DATA;
    msg.body.msgh_descriptor_count = 0;
    msg.type = SKYGLOW_FEEDBACK_DATA;

    strlcpy(msg.topic,  [bundleId UTF8String] ?: "", sizeof(msg.topic));
    strlcpy(msg.reason, [reason UTF8String]   ?: "", sizeof(msg.reason));

    kr = mach_msg(&msg.header, MACH_SEND_MSG, msg.header.msgh_size, 0,
                  MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[SGN] Feedback send failed: %s", mach_error_string(kr));
    }

    mach_port_deallocate(mach_task_self(), daemonPort);
}

// ═══════════════════════════════════════════════
#pragma mark - Notification Delivery
// ═══════════════════════════════════════════════

/// Deliver a push notification into the system notification infrastructure.
/// Routes to the correct API based on iOS version.
static void DeliverNotification(NSString *topic, NSDictionary *userInfo) {
    if (!topic.length) return;
    if (!userInfo) userInfo = @{};

    // Build APSIncomingMessage
    Class APSClass = objc_getClass("APSIncomingMessage");
    id apsMessage = nil;
    if (APSClass) {
        apsMessage = [[APSClass alloc] initWithTopic:topic userInfo:userInfo];
    }

    double cf = kCFCoreFoundationVersionNumber;

    if (cf < 700.0) {
        // ── Pre-iOS 6 ──
        id server = [objc_getClass("SBRemoteNotificationServer") sharedInstance];
        if ([server respondsToSelector:@selector(connection:didReceiveMessageForTopic:userInfo:)]) {
            [server connection:nil didReceiveMessageForTopic:topic userInfo:userInfo];
        }
    } else if (cf < 1200.0) {
        // ── iOS 6 / 7 / 8 ──
        id server = [objc_getClass("SBRemoteNotificationServer") sharedInstance];
        if (server && apsMessage) {
            [server connection:nil didReceiveIncomingMessage:apsMessage];
        }
    } else if (cf < 1300.0) {
        // ── iOS 9 ──
        id userNS  = [objc_getClass("UNUserNotificationServer") sharedInstance];
        id registrar  = GetIvar(userNS, "_registrarConnectionListener");
        id remoteSrv  = GetIvar(registrar, "_remoteNotificationServer");
        if (!remoteSrv) remoteSrv = GetIvar(registrar, "_removeNotificationServer");

        if (remoteSrv && apsMessage) {
            [remoteSrv connection:nil didReceiveIncomingMessage:apsMessage];
        }
    } else {
        // ── iOS 10+ ──
        id userNS    = [objc_getClass("UNSUserNotificationServer") sharedInstance];
        id remoteSrv = GetIvar(userNS, "_remoteNotificationService");

        if (apsMessage && [apsMessage respondsToSelector:@selector(setTimestamp:)]) {
            [apsMessage setTimestamp:[NSDate date]];
        }
        if (remoteSrv && apsMessage) {
            [remoteSrv connection:nil didReceiveIncomingMessage:apsMessage];
        }
    }
}

// ═══════════════════════════════════════════════
#pragma mark - Push Receiver Mach Server
// ═══════════════════════════════════════════════

/// Process a single push request from the daemon.
static void HandlePushMessage(MachPushRequestMessage *req) {
    NSString *topic = [NSString stringWithUTF8String:req->topic];
    if (!topic.length) return;

    NSDictionary *userInfo = nil;
    if (req->userInfoLength > 0 && req->userInfoLength <= SKYGLOW_MAX_USERINFO_SIZE) {
        NSData *data = [NSData dataWithBytes:req->userInfoData length:req->userInfoLength];
        id parsed = [NSPropertyListSerialization propertyListWithData:data
                                                              options:NSPropertyListImmutable
                                                               format:NULL
                                                                error:NULL];
        if ([parsed isKindOfClass:[NSDictionary class]]) {
            userInfo = parsed;
        }
    }

    NSLog(@"[SGN] Delivering push for topic: %@", topic);
    DeliverNotification(topic, userInfo ?: @{});
}

/// Mach message receive loop (runs on background thread).
static void PushReceiverLoop(void) {
    while (1) {
        MachPushRequestMessage req;
        memset(&req, 0, sizeof(req));

        kern_return_t kr = mach_msg(&req.header, MACH_RCV_MSG, 0, sizeof(req),
                                    gPushReceiverPort, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            NSLog(@"[SGN] Push recv error: %s", mach_error_string(kr));
            continue;
        }
        if (req.type == SKYGLOW_REQUEST_PUSH) {
            HandlePushMessage(&req);
        }
    }
}

/// Set up the push receiver Mach service and start the listener.
static BOOL StartPushReceiver(void) {
    kern_return_t kr;

    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &gPushReceiverPort);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[SGN] Push port alloc failed: %s", mach_error_string(kr));
        return NO;
    }

    kr = mach_port_insert_right(mach_task_self(), gPushReceiverPort, gPushReceiverPort,
                                MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[SGN] Push port send right failed: %s", mach_error_string(kr));
        return NO;
    }

    mach_port_t bsPort = MACH_PORT_NULL;
    task_get_bootstrap_port(mach_task_self(), &bsPort);

    kr = bootstrap_register(bsPort, SKYGLOW_MACH_SERVICE_NAME_PUSH, gPushReceiverPort);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[SGN] Push service register failed: %s", mach_error_string(kr));
        return NO;
    }

    NSLog(@"[SGN] Push receiver registered on %s", SKYGLOW_MACH_SERVICE_NAME_PUSH);
    return YES;
}

// ═══════════════════════════════════════════════
#pragma mark - Debug: Auto-Register Test App
// ═══════════════════════════════════════════════

static void AutoRegisterTestApp(void) {
    NSString *testBundleID = @"com.apple.Preferences";

    NSLog(@"[SGN] Auto-registering %@ for testing...", testBundleID);

    for (int attempt = 0; attempt < 5; attempt++) {
        NSData *token = RequestTokenFromDaemon(testBundleID);
        if (token) {
            // Also ensure it's in the appStatus plist so settings UI shows it
            EnsureAppInPlist(testBundleID);

            const unsigned char *bytes = (const unsigned char *)[token bytes];
            NSMutableString *hex = [NSMutableString stringWithCapacity:token.length * 2];
            for (NSUInteger i = 0; i < token.length; i++) {
                [hex appendFormat:@"%02x", bytes[i]];
            }
            NSLog(@"[SGN] Token for %@: %@", testBundleID, hex);
            return;
        }

        NSLog(@"[SGN] Token request failed (attempt %d/5), retrying in 5s...", attempt + 1);
        [NSThread sleepForTimeInterval:5.0];
    }

    NSLog(@"[SGN] Failed to get token for %@ after 5 attempts", testBundleID);
}

// ═══════════════════════════════════════════════
#pragma mark - Hooks
// ═══════════════════════════════════════════════

// ── App Uninstall: notify daemon to clean up tokens ──

%hook SBApplicationUninstallationOperation

- (void)main {
    NSString *bundleId = [(id)self valueForKey:@"_bundleIdentifier"];
    if (bundleId.length) {
        NSLog(@"[SGN] App uninstalling: %@", bundleId);
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            SendFeedbackToDaemon(bundleId, @"App uninstalled");
        });
    }
    %orig;
}

%end

// ── Remote Notification Registration ──

%hook SBRemoteNotificationServer

- (int)registerApplication:(id)application
            forEnvironment:(id)environment
                 withTypes:(int)notificationTypes {

    NSString *bundleId = [application bundleIdentifier];
    NSLog(@"[SGN] registerApplication:%@ env:%@ types:%d", bundleId, environment, notificationTypes);

    if (!bundleId.length) return %orig;

    // ── Client setup (same as original) ──

    BOOL needsUpdate = NO;

    NSMutableDictionary *clientsByBundle = [self valueForKey:@"_bundleIdentifiersToClients"];
    SBRemoteNotificationClient *client = [clientsByBundle objectForKey:bundleId];

    if (!client) {
        client = [[%c(SBRemoteNotificationClient) alloc] initWithBundleIdentifier:bundleId];
        [clientsByBundle setObject:client forKey:bundleId];
        needsUpdate = YES;
    }

    if (![[client environment] isEqual:environment]) {
        [client setEnvironment:environment];
        needsUpdate = YES;
    }

    int requestedTypes = notificationTypes & 0xF;
    if ([client appEnabledTypes] != requestedTypes) {
        [client setAppEnabledTypes:requestedTypes];
        needsUpdate = YES;
    }

    // ── Connection lookup ──

    NSMutableDictionary *envToConn = [self valueForKey:@"_environmentsToConnections"];
    id connection = [envToConn objectForKey:environment];

    if (!connection) {
        [self performSelector:@selector(calculateTopics)];
        connection = [envToConn objectForKey:environment];
    }

    BOOL hasValidAPNS = NO;
    if (connection && [connection respondsToSelector:@selector(hasIdentity)]) {
        hasValidAPNS = ((intptr_t)[connection performSelector:@selector(hasIdentity)]) != 0;
    }

    // ── Permission alert logic ──

    int presentedTypes = [client settingsPresentedTypes];

    if ((notificationTypes & 0x8) != 0 && (presentedTypes & 0x8) == 0) {
        int alertTypes = (requestedTypes != 0x8) ? 0xF : 0x8;
        id alert = [[%c(SBRemoteNotificationPermissionAlert) alloc]
                    initWithApplication:application notificationTypes:alertTypes];
        if (alert) {
            SBAlertItemsController *ctrl = [%c(SBAlertItemsController) sharedInstance];
            [ctrl deactivateAlertItemsOfClass:%c(SBRemoteNotificationPermissionAlert)];
            [ctrl activateAlertItem:alert];
            [client setSettingsPresentedTypes:presentedTypes | requestedTypes];
        }
    } else if ((notificationTypes & ~presentedTypes & 0x7) != 0) {
        id alert = [[%c(SBRemoteNotificationPermissionAlert) alloc]
                    initWithApplication:application notificationTypes:0x7];
        if (alert) {
            SBAlertItemsController *ctrl = [%c(SBAlertItemsController) sharedInstance];
            [ctrl deactivateAlertItemsOfClass:%c(SBRemoteNotificationPermissionAlert)];
            [ctrl activateAlertItem:alert];
            [client setSettingsPresentedTypes:presentedTypes | requestedTypes];
        }
    }

    // ── Token: Skyglow or APNS ──

    NSData *token = nil;

    if (ShouldUseSkyglowForApp(bundleId)) {
        NSLog(@"[SGN] Using Skyglow for %@", bundleId);
        token = RequestTokenFromDaemon(bundleId);
    } else {
        NSLog(@"[SGN] Using APNS for %@", bundleId);
        if (hasValidAPNS) {
            token = [connection performSelector:@selector(publicToken)];
        }
    }

    if (token) {
        NSLog(@"[SGN] Delivering token (%lu bytes) to %@", (unsigned long)token.length, bundleId);
        if ([application respondsToSelector:@selector(remoteApplication)]) {
            SBRemoteApplication *remoteApp = [(UIApplication *)application remoteApplication];
            [remoteApp remoteNotificationRegistrationSucceededWithDeviceToken:token];
        }
        [client setLastKnownDeviceToken:token];
    } else {
        NSLog(@"[SGN] No token available for %@", bundleId);
    }

    // ── Persist & recalculate ──

    if (needsUpdate) {
        [[%c(SBApplicationPersistence) sharedInstance]
            setArchivedObject:client
                       forKey:@"SBRemoteNotificationClient"
    bundleOrDisplayIdentifier:bundleId];
        [self performSelector:@selector(calculateTopics)];
    }

    return needsUpdate;
}

%end

// ═══════════════════════════════════════════════
#pragma mark - Constructor
// ═══════════════════════════════════════════════

%ctor {
    // 1. Start push receiver (Mach server for daemon → SpringBoard delivery)
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        if (StartPushReceiver()) {
            PushReceiverLoop(); // blocks forever
        }
    });

    // 2. Debug: auto-register a test app after daemon has had time to start
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
        [NSThread sleepForTimeInterval:15.0];
        AutoRegisterTestApp();
    });
}
