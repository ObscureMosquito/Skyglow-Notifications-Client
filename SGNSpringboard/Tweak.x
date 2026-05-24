#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <bootstrap.h>
#include <fcntl.h>
#include <unistd.h>
#import "../Skyglow-Notifications-Daemon/SGControlChannel.h"
#import "../Skyglow-Notifications-Daemon/SGControlChannelProtocol.h"

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

static SGControlChannel *gSGCDaemonClient = nil;  // outbound: token + feedback
static SGControlChannel *gSGCSBServer     = nil;  // inbound: push + input-app commands

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

#pragma mark - Daemon Communication (SGControlChannel client)

/* Cached "is the daemon enabled?" with a vnode watcher on the prefs plist.
 * Replaces a per-call file read; falls back to direct reads if the plist
 * doesn't exist yet at SB launch. */
static BOOL              gDaemonEnabledCached = YES;
static BOOL              gPrefsWatcherActive  = NO;
static dispatch_source_t gPrefsWatcherSource  = NULL;

static void SGN_LoadDaemonEnabledFromPlist(void) {
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath];
    NSNumber *enabled = [prefs objectForKey:@"isEnabled"];
    gDaemonEnabledCached = (enabled == nil) ? YES : [enabled boolValue];
}

static void SGN_StartPrefsPlistWatcher(void);

static void SGN_HandlePrefsPlistEvent(unsigned long flags) {
    SGN_LoadDaemonEnabledFromPlist();
    if (flags & (DISPATCH_VNODE_DELETE | DISPATCH_VNODE_RENAME)) {
        /* Atomic plist rewrite — re-arm against the new inode. */
        dispatch_source_t old = gPrefsWatcherSource;
        gPrefsWatcherSource = NULL;
        gPrefsWatcherActive = NO;
        if (old) dispatch_source_cancel(old);
        SGN_StartPrefsPlistWatcher();
    }
}

static void SGN_StartPrefsPlistWatcher(void) {
    int fd = open([kPrefsPlistPath fileSystemRepresentation], O_EVTONLY);
    if (fd < 0) return;

    dispatch_queue_t q = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    dispatch_source_t src = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_VNODE, (uintptr_t)fd,
        DISPATCH_VNODE_WRITE | DISPATCH_VNODE_EXTEND |
        DISPATCH_VNODE_DELETE | DISPATCH_VNODE_RENAME, q);
    if (!src) { close(fd); return; }

    gPrefsWatcherSource = src;
    gPrefsWatcherActive = YES;

    dispatch_source_set_event_handler(src, ^{
        SGN_HandlePrefsPlistEvent(dispatch_source_get_data(src));
    });
    dispatch_source_set_cancel_handler(src, ^{
        close(fd);
    });
    dispatch_resume(src);
}

/* Fail-fast guard so we don't bootstrap-loop while the user has the daemon
 * turned off — bootstrap_look_up would just keep returning errors. */
static BOOL SGN_DaemonIsEnabled(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        SGN_LoadDaemonEnabledFromPlist();
        SGN_StartPrefsPlistWatcher();
    });
    if (!gPrefsWatcherActive) {
        SGN_LoadDaemonEnabledFromPlist();
        SGN_StartPrefsPlistWatcher();
    }
    return gDaemonEnabledCached;
}

/* Semaphore wait preserves the existing synchronous contract — the caller
 * (DeliverSkyglowToken) is already on a background queue. */
static NSData *RequestTokenFromDaemon(NSString *bundleID) {
    if (!bundleID.length) return nil;

    if (!SGN_DaemonIsEnabled()) {
        NSLog(@"[SGN] RequestToken: daemon disabled in Settings — failing fast for %@", bundleID);
        return nil;
    }
    if (!gSGCDaemonClient) {
        NSLog(@"[SGN] RequestToken: control channel not yet initialised for %@", bundleID);
        return nil;
    }

    SGCTokenRequestPayload payload;
    memset(&payload, 0, sizeof(payload));
    strlcpy(payload.bundleID, [bundleID UTF8String], sizeof(payload.bundleID));
    NSData *payloadData = [NSData dataWithBytes:&payload length:sizeof(payload)];

    __block NSData *result = nil;
    __block SGControlError finalErr = SGCERR_TIMEOUT;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);

    [gSGCDaemonClient sendRequest:SGCMSG_TOKEN_REQUEST
                          payload:payloadData
                          timeout:0
                       completion:^(SGControlError err, const SGControlChannelMessage *response) {
        finalErr = err;
        if (err == SGCERR_OK && response &&
            response->payloadLength >= sizeof(SGCTokenResponsePayload)) {
            SGCTokenResponsePayload *resp = (SGCTokenResponsePayload *)response->payload;
            if (resp->tokenLength > 0 && resp->tokenLength <= SG_CONTROL_MAX_TOKEN_SIZE) {
                result = [[NSData alloc] initWithBytes:resp->tokenData length:resp->tokenLength];
            }
        }
        dispatch_semaphore_signal(sema);
    }];

    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
    dispatch_release(sema);

    if (finalErr != SGCERR_OK) {
        NSLog(@"[SGN] RequestToken: failed for %@ err=%d", bundleID, finalErr);
    }
    return [result autorelease];
}

static void SendFeedbackToDaemon(NSString *bundleId, NSString *reason) {
    if (!bundleId.length) return;
    if (!SGN_DaemonIsEnabled() || !gSGCDaemonClient) return;

    SGCFeedbackPayload payload;
    memset(&payload, 0, sizeof(payload));
    strlcpy(payload.bundleID, [bundleId UTF8String], sizeof(payload.bundleID));
    strlcpy(payload.reason,
            [reason UTF8String] ?: "uninstalled",
            sizeof(payload.reason));
    NSData *payloadData = [NSData dataWithBytes:&payload length:sizeof(payload)];

    [gSGCDaemonClient sendRequest:SGCMSG_FEEDBACK
                          payload:payloadData
                          timeout:0
                       completion:nil];
}

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

/* Main-thread only. Exceptions deliberately propagate so the caller can
 * translate to SGCERR_INTERNAL. */
static void DeliverNotification(NSString *topic, NSDictionary *userInfo) {
    if (!topic.length) return;
    NSDictionary *apnsPayload = WrapInAPNSFormat(userInfo ?: @{});

    double cfVersion = kCFCoreFoundationVersionNumber;

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
}

#pragma mark - SGControlChannel Server (push delivery + prefs commands)

static void StartSpringBoardControlChannel(void) {
    gSGCSBServer = [[SGControlChannel serverWithServiceName:SKYGLOW_CONTROL_SERVICE_SPRINGBOARD] retain];

    /* PUSH_DELIVERY — hop to main for DeliverNotification (SBRemote/UN servers
     * are main-only); ACK after delivery so silent failures don't lose pushes. */
    [gSGCSBServer registerHandler:^(const SGControlChannelMessage *req,
                                    SGControlReplyBlock reply,
                                    SGControlReplyErrorBlock replyError) {
        if (req->payloadLength < offsetof(SGCPushDeliveryPayload, userInfoData)) {
            replyError(SGCERR_INVALID_REQUEST, @"push delivery payload too short");
            return;
        }
        SGCPushDeliveryPayload *pd = (SGCPushDeliveryPayload *)req->payload;
        NSString *topic = [[NSString alloc] initWithBytes:pd->bundleID
                                                   length:strnlen(pd->bundleID, sizeof(pd->bundleID))
                                                 encoding:NSUTF8StringEncoding];
        NSDictionary *userInfo = nil;
        if (pd->userInfoLength > 0 && pd->userInfoLength <= SG_CONTROL_MAX_USERINFO_SIZE) {
            NSData *data = [NSData dataWithBytes:pd->userInfoData length:pd->userInfoLength];
            userInfo = [NSPropertyListSerialization propertyListWithData:data
                                                                 options:NSPropertyListImmutable
                                                                  format:NULL error:NULL];
        }

        SGControlReplyBlock      replyCopy      = [reply copy];
        SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
        NSDictionary            *userInfoRet    = [userInfo retain];

        dispatch_async(dispatch_get_main_queue(), ^{
            BOOL ok = YES;
            NSString *failReason = nil;
            @try {
                NSLog(@"[SGN] Delivering push for topic: %@", topic);
                DeliverNotification(topic, userInfoRet);
            } @catch (NSException *e) {
                NSLog(@"[SGN] Push delivery threw: %@", e);
                ok = NO;
                failReason = [e reason] ?: @"delivery exception";
            }
            if (ok) replyCopy(SGCMSG_GENERIC_ACK, nil);
            else    replyErrorCopy(SGCERR_INTERNAL, failReason);

            [topic release];
            [userInfoRet release];
            [replyCopy release];
            [replyErrorCopy release];
        });
    } forMessageType:SGCMSG_PUSH_DELIVERY];

    /* SGCMSG_REGISTER_INPUT_APP — user added an app to the Skyglow list. */
    [gSGCSBServer registerHandler:^(const SGControlChannelMessage *req,
                                    SGControlReplyBlock reply,
                                    SGControlReplyErrorBlock replyError) {
        if (req->payloadLength < sizeof(SGCBundleIdPayload)) {
            replyError(SGCERR_INVALID_REQUEST, @"register input payload too short");
            return;
        }
        SGCBundleIdPayload *bp = (SGCBundleIdPayload *)req->payload;
        NSString *bundleId = [[NSString alloc] initWithBytes:bp->bundleID
                                                      length:strnlen(bp->bundleID, sizeof(bp->bundleID))
                                                    encoding:NSUTF8StringEncoding];
        if (bundleId.length) {
            if (kCFCoreFoundationVersionNumber < 1200.0) {
                /* SBRemoteNotificationServer is main-thread-only on classic iOS. */
                NSString *bundleIdRet = [bundleId retain];
                dispatch_async(dispatch_get_main_queue(), ^{
                    id app = SBApp_LookupByIdentifier(bundleIdRet);
                    SBRemoteNotificationServer *server = [%c(SBRemoteNotificationServer) sharedInstance];
                    if (app && server) {
                        [server registerApplication:app forEnvironment:@"production" withTypes:7];
                    }
                    [bundleIdRet release];
                });
            } else {
                DeliverSkyglowToken(bundleId);
            }
        }
        [bundleId release];
        reply(SGCMSG_GENERIC_ACK, nil);
    } forMessageType:SGCMSG_REGISTER_INPUT_APP];

    /* SGCMSG_UNREGISTER_INPUT_APP — user removed an app from the Skyglow list. */
    [gSGCSBServer registerHandler:^(const SGControlChannelMessage *req,
                                    SGControlReplyBlock reply,
                                    SGControlReplyErrorBlock replyError) {
        if (req->payloadLength < sizeof(SGCBundleIdPayload)) {
            replyError(SGCERR_INVALID_REQUEST, @"unregister input payload too short");
            return;
        }
        SGCBundleIdPayload *bp = (SGCBundleIdPayload *)req->payload;
        NSString *bundleId = [[NSString alloc] initWithBytes:bp->bundleID
                                                      length:strnlen(bp->bundleID, sizeof(bp->bundleID))
                                                    encoding:NSUTF8StringEncoding];
        if (bundleId.length) {
            NSMutableDictionary *sndpPrefs = [[NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath] mutableCopy] ?: [NSMutableDictionary dictionary];
            NSMutableDictionary *appStatus = [[sndpPrefs objectForKey:@"appStatus"] mutableCopy] ?: [NSMutableDictionary dictionary];
            [appStatus removeObjectForKey:bundleId];
            [sndpPrefs setObject:appStatus forKey:@"appStatus"];
            [sndpPrefs writeToFile:kPrefsPlistPath atomically:YES];
            [appStatus release];
            [sndpPrefs release];
            NSString *bidCopy = [bundleId copy];
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                SendFeedbackToDaemon(bidCopy, @"User removed from Skyglow");
                [bidCopy release];
            });
        }
        [bundleId release];
        reply(SGCMSG_GENERIC_ACK, nil);
    } forMessageType:SGCMSG_UNREGISTER_INPUT_APP];

    if (![gSGCSBServer start]) {
        NSLog(@"[SGN] SGControlChannel server failed to start on %s", SKYGLOW_CONTROL_SERVICE_SPRINGBOARD);
        [gSGCSBServer release];
        gSGCSBServer = nil;
    }
}

static void StartDaemonControlChannelClient(void) {
    gSGCDaemonClient = [[SGControlChannel clientForServiceName:SKYGLOW_CONTROL_SERVICE_DAEMON] retain];
    [gSGCDaemonClient start];
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

static void SGN_InstallTokenGuard(void);

static void CompleteRegistrationWithSkyglowToken(id application, id environment, int notificationTypes, NSData *token) {
    NSString *bundleId = [application bundleIdentifier];
    if (!bundleId.length || !token) return;

    SGN_InstallTokenGuard();

    SBRemoteNotificationServer *server = [%c(SBRemoteNotificationServer) sharedInstance];

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
        NSMutableDictionary *prefs = [[NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath] mutableCopy] ?: [NSMutableDictionary dictionary];
        NSMutableDictionary *appStatus = [[prefs objectForKey:@"appStatus"] mutableCopy] ?: [NSMutableDictionary dictionary];
        [appStatus setObject:@YES forKey:sPendingBundleId];
        [prefs setObject:appStatus forKey:@"appStatus"];
        [prefs writeToFile:kPrefsPlistPath atomically:YES];
        [appStatus release];
        [prefs release];

        if (sPendingIsModern) {
            DeliverSkyglowToken(sPendingBundleId);
        } else {
            NSData *token = RequestTokenFromDaemon(sPendingBundleId);
            if (token) {
                CompleteRegistrationWithSkyglowToken(sPendingApp, sPendingEnv, sPendingTypes, token);
            } else {
                NSLog(@"[SGN] Alert: failed to get token for %@", sPendingBundleId);
                ShowTokenFailureAlert(sPendingBundleId);
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
            NSData *token = RequestTokenFromDaemon(bundleId);
            if (token) {
                NSLog(@"[SGN] Classic hook: completing Skyglow registration for %@", bundleId);
                CompleteRegistrationWithSkyglowToken(application, environment, notificationTypes, token);
                return 1;
            }
            NSLog(@"[SGN] Classic hook: token fetch failed for %@, delivering nothing", bundleId);
            return 0;
        } else {
            NSLog(@"[SGN] Classic hook: APNs pass-through for %@", bundleId);
            return %orig;
        }
    }

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
        Method m = class_getInstanceMethod(classes[i], sel);
        if (!m) continue;
        if (class_getInstanceMethod(class_getSuperclass(classes[i]), sel) == m) continue;

        NSLog(@"[SGN] TokenGuard: hooking %s for token delivery interception",
              class_getName(classes[i]));
        MSHookMessageEx(classes[i], sel, (IMP)SGN_Hook_TokenDelivery,
                        (IMP *)&SGN_Original_TokenDelivery);
        break;
    }
    free(classes);
    });
}

#pragma mark - Constructor

%ctor {
    StartSpringBoardControlChannel();
    StartDaemonControlChannelClient();

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
}
