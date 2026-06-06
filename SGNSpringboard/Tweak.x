#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <bootstrap.h>
#import "../Skyglow-Notifications-Daemon/SGControlChannel.h"
#import "../Skyglow-Notifications-Daemon/SGControlChannelProtocol.h"
#import "../Skyglow-Notifications-Daemon/SGSharedConstants.h"
#import "../Skyglow-Notifications-Daemon/SGCompatibilityShim.h"

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
- (void)unregisterApplication:(id)application;
- (NSArray *)_allPushRegisteredThirdPartyBundleIDs;
@end

@interface UNNotificationRegistrarConnectionListener : NSObject
- (void)requestTokenForRemoteNotificationsForBundleIdentifier:(NSString *)bundleIdentifier withResult:(id)resultBlock;
- (void)invalidateTokenForRemoteNotificationsForBundleIdentifier:(NSString *)bundleIdentifier;
@end

@interface UNRemoteNotificationServer : NSObject
@end

static NSString *const kPrefsPlistPath = SG_PREFS_PLIST_PATH;

static SGControlChannel *gSGCDaemonClient = nil;
static SGControlChannel *gSGCSBServer     = nil;

#pragma mark - Utility Helpers

static void SGNCopyCString(char *dst, size_t dstSize, const char *src) {
    if (!dst || dstSize == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t i = 0;
    while (i + 1 < dstSize && src[i] != '\0') {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

static id GetIvar(id obj, const char *name) {
    if (!obj || !name) return nil;
    Ivar iv = class_getInstanceVariable(object_getClass(obj), name);
    return iv ? object_getIvar(obj, iv) : nil;
}

static id SBApp_LookupByIdentifier(NSString *bundleId) {
    SBApplicationController *ctrl = [%c(SBApplicationController) sharedInstance];
    id app = nil;
    if ([ctrl respondsToSelector:@selector(applicationWithBundleIdentifier:)]) {
        app = [ctrl applicationWithBundleIdentifier:bundleId];
    } else {
        app = [ctrl applicationWithDisplayIdentifier:bundleId];
    }
    if (!app) return nil;

    NSString *reportedId = nil;
    if ([app respondsToSelector:@selector(bundleIdentifier)]) {
        reportedId = [app performSelector:@selector(bundleIdentifier)];
    } else if ([app respondsToSelector:@selector(displayIdentifier)]) {
        reportedId = [app performSelector:@selector(displayIdentifier)];
    }
    if (!reportedId.length) return nil;
    if (![reportedId isEqualToString:bundleId]) return nil;
    return app;
}

static NSMutableDictionary *SGN_OwnedPlistAt(NSString *path) {
    NSMutableDictionary *d = [[NSMutableDictionary alloc] initWithContentsOfFile:path];
    return d ?: [[NSMutableDictionary alloc] init];
}

static NSMutableDictionary *SGN_OwnedMutableDictForKey(NSDictionary *src, NSString *key) {
    NSDictionary *inner = [src objectForKey:key];
    return inner ? [inner mutableCopy] : [[NSMutableDictionary alloc] init];
}

static NSMutableArray *SGN_OwnedMutableArrayForKey(NSDictionary *src, NSString *key) {
    NSArray *inner = [src objectForKey:key];
    return inner ? [inner mutableCopy] : [[NSMutableArray alloc] init];
}

static void EnsureAppInPlist(NSString *bundleId) {
    if (!bundleId.length) return;
    NSMutableDictionary *prefs     = SGN_OwnedPlistAt(kPrefsPlistPath);
    NSMutableDictionary *appStatus = SGN_OwnedMutableDictForKey(prefs, @"appStatus");
    if ([appStatus objectForKey:bundleId] != nil) {
        [appStatus release];
        [prefs release];
        return;
    }
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

static void ScheduleAppDeletion(NSString *bundleId) {
    if (!bundleId.length) return;
    NSMutableDictionary *prefs = SGN_OwnedPlistAt(kPrefsPlistPath);

    NSMutableDictionary *appStatus = SGN_OwnedMutableDictForKey(prefs, @"appStatus");
    [appStatus removeObjectForKey:bundleId];
    [prefs setObject:appStatus forKey:@"appStatus"];
    [appStatus release];

    NSMutableArray *pending = SGN_OwnedMutableArrayForKey(prefs, @"pendingDeletions");
    if (![pending containsObject:bundleId]) {
        [pending addObject:bundleId];
    }
    [prefs setObject:pending forKey:@"pendingDeletions"];
    [pending release];

    [prefs writeToFile:kPrefsPlistPath atomically:YES];
    [prefs release];
}

#pragma mark - Daemon Communication (SGControlChannel client)

static void SendDeleteAppToDaemon(NSString *bundleId) {
    if (!bundleId.length || !gSGCDaemonClient) return;

    SGCBundleIdPayload payload;
    memset(&payload, 0, sizeof(payload));
    SGNCopyCString(payload.bundleID, sizeof(payload.bundleID), [bundleId UTF8String]);

    [gSGCDaemonClient sendRequest:SGCMSG_DELETE_APP
                          payload:[NSData dataWithBytes:&payload length:sizeof(payload)]
                          timeout:0
                       completion:nil];
}

static void SGN_DeliverSuccess(NSString *bundleId, id application, id environment,
                               int notificationTypes, NSData *token);

static void SGN_DeregisterAppNatively(NSString *bundleId);

static NSArray *SGN_AllNativelyRegisteredBundles(void);
static BOOL     SGN_BundleRegisteredWithNativePush(NSString *bundleId);

static id SGN_RemoteAppForBundle(NSString *bundleId) {
    id app = SBApp_LookupByIdentifier(bundleId);
    if (!app || ![app respondsToSelector:@selector(remoteApplication)]) return nil;
    return [app performSelector:@selector(remoteApplication)];
}

static void SGN_DeliverFailure(NSString *bundleId, NSString *reason) {
    id remoteApp = SGN_RemoteAppForBundle(bundleId);
    if (!remoteApp) return;

    NSDictionary *info = reason
        ? [NSDictionary dictionaryWithObject:reason forKey:NSLocalizedDescriptionKey]
        : nil;
    NSError *err = [NSError errorWithDomain:@"com.skyglow.sgn" code:-1 userInfo:info];

    SEL sel = @selector(remoteNotificationRegistrationFailedWithError:);
    if ([remoteApp respondsToSelector:sel]) {
        [remoteApp performSelector:sel withObject:err];
        return;
    }
    SEL altSel = NSSelectorFromString(@"_remoteNotificationRegistrationFailedWithError:");
    if ([remoteApp respondsToSelector:altSel]) {
        [remoteApp performSelector:altSel withObject:err];
        return;
    }
    NSLog(@"[SGN] No failure selector available on remoteApp for %@", bundleId);
}

static void SGN_AsyncFetchAndDeliverToken(NSString *bundleId,
                                          id application,
                                          id environment,
                                          int notificationTypes) {
    NSString *safeBundleId = [bundleId copy];
    id        safeApp      = application ? [application retain] : nil;
    id        safeEnv      = environment ? [environment retain] : nil;

    if (!gSGCDaemonClient) {
        NSLog(@"[SGN] AsyncFetch: control channel not initialised for %@", safeBundleId);
        dispatch_async(dispatch_get_main_queue(), ^{
            SGN_DeliverFailure(safeBundleId, @"control channel not initialised");
            [safeBundleId release];
            [safeApp release];
            [safeEnv release];
        });
        return;
    }

    SGCTokenRequestPayload payload;
    memset(&payload, 0, sizeof(payload));
    SGNCopyCString(payload.bundleID, sizeof(payload.bundleID), [safeBundleId UTF8String]);
    NSData *payloadData = [NSData dataWithBytes:&payload length:sizeof(payload)];

    [gSGCDaemonClient sendRequest:SGCMSG_TOKEN_REQUEST
                          payload:payloadData
                          timeout:0
                       completion:^(SGControlError err, const SGControlChannelMessage *response) {
        NSData *token = nil;
        if (err == SGCERR_OK && response &&
            response->payloadLength >= sizeof(SGCTokenResponsePayload)) {
            SGCTokenResponsePayload *resp = (SGCTokenResponsePayload *)response->payload;
            if (resp->tokenLength > 0 && resp->tokenLength <= SG_CONTROL_MAX_TOKEN_SIZE) {
                token = [NSData dataWithBytes:resp->tokenData length:resp->tokenLength];
            }
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                if (token) {
                    SGN_DeliverSuccess(safeBundleId, safeApp, safeEnv,
                                       notificationTypes, token);
                } else {
                    NSString *reason = [NSString stringWithFormat:
                        @"daemon unreachable (err=%d)", err];
                    SGN_DeliverFailure(safeBundleId, reason);
                }
            } @catch (NSException *e) {
                NSLog(@"[SGN] Delivery exception for %@: %@", safeBundleId, e);
            }
            [safeBundleId release];
            [safeApp release];
            [safeEnv release];
        });
    }];
}

#pragma mark - Notification Delivery

static NSDictionary *WrapInAPNSFormat(NSDictionary *flat) {
    if ([flat[@"aps"] isKindOfClass:[NSDictionary class]]) {
        return flat;
    }

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

    if (SGN_IS_PRE_IOS_6) {
        id server = [NSClassFromString(@"SBRemoteNotificationServer") performSelector:@selector(sharedInstance)];
        if (server) {
            SEL sel = @selector(connection:didReceiveMessageForTopic:userInfo:);
            void (*send)(id, SEL, id, id, id) = (void (*)(id, SEL, id, id, id))objc_msgSend;
            send(server, sel, nil, topic, apnsPayload);
        }
    } else if (SGN_IS_PRE_IOS_9) {
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
        if (!SG_IsIdentifierStringSafe(topic)) {
            [topic release];
            replyError(SGCERR_INVALID_REQUEST, @"push delivery bundle id invalid");
            return;
        }
        NSDictionary *userInfo = nil;
        if (pd->userInfoLength > 0 && pd->userInfoLength <= SG_CONTROL_MAX_USERINFO_SIZE) {
            /* Inner length must fit within the outer payload — defense in
             * depth (the channel parser now also validates payloadLength
             * against msgh_size, so a peer can't claim more than was
             * actually sent). */
            size_t innerNeeded = (size_t)pd->userInfoLength + offsetof(SGCPushDeliveryPayload, userInfoData);
            if (innerNeeded > req->payloadLength) {
                [topic release];
                replyError(SGCERR_INVALID_REQUEST, @"push delivery userInfo length exceeds payload");
                return;
            }
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
        if (!SG_IsIdentifierStringSafe(bundleId)) {
            [bundleId release];
            replyError(SGCERR_INVALID_REQUEST, @"register input bundle id invalid");
            return;
        }
        /* Bundle existence check.  SBApplicationController has to be hit on
         * the main queue (it's not thread-safe), so we hop, look up, and
         * dispatch the reply from there.  Previously this handler ACKed
         * unconditionally before the async lookup even ran, which let the
         * debug menu happily "register" arbitrary garbage strings. */
        NSString *bundleIdRet = [bundleId retain];
        SGControlReplyBlock      replyCopy      = [reply copy];
        SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
        dispatch_async(dispatch_get_main_queue(), ^{
            id app = SBApp_LookupByIdentifier(bundleIdRet);
            if (!app) {
                replyErrorCopy(SGCERR_NOT_FOUND,
                    [NSString stringWithFormat:@"No installed application has bundle id '%@'.", bundleIdRet]);
                [bundleIdRet release];
                [replyCopy release];
                [replyErrorCopy release];
                return;
            }
            if (SGN_IS_PRE_IOS_9) {
                SBRemoteNotificationServer *server = [%c(SBRemoteNotificationServer) sharedInstance];
                if (server) {
                    [server registerApplication:app forEnvironment:@"production" withTypes:7];
                }
            } else {
                SGN_AsyncFetchAndDeliverToken(bundleIdRet, nil, nil, 0);
            }
            replyCopy(SGCMSG_GENERIC_ACK, nil);
            [bundleIdRet release];
            [replyCopy release];
            [replyErrorCopy release];
        });
        [bundleId release];
    } forMessageType:SGCMSG_REGISTER_INPUT_APP];

    [gSGCSBServer registerHandler:^(const SGControlChannelMessage *req,
                                    SGControlReplyBlock reply,
                                    SGControlReplyErrorBlock replyError) {
        NSArray *bundles = SGN_AllNativelyRegisteredBundles();

        NSMutableData *body = [NSMutableData data];
        uint16_t count = 0;
        for (NSString *bid in bundles) {
            const char *bidC = [bid UTF8String];
            if (!bidC) continue;
            NSUInteger len = strlen(bidC);
            if (len == 0 || len > 0xFFFF) continue;
            NSUInteger projected = offsetof(SGCBundleIdListPayload, data)
                                  + [body length] + 2 + len;
            if (projected > SG_CONTROL_MAX_PAYLOAD) break;
            uint16_t l = (uint16_t)len;
            [body appendBytes:&l length:sizeof(l)];
            [body appendBytes:bidC length:len];
            count++;
        }

        NSMutableData *out = [NSMutableData dataWithCapacity:
            offsetof(SGCBundleIdListPayload, data) + [body length]];
        [out appendBytes:&count length:sizeof(count)];
        [out appendData:body];

        reply(SGCMSG_BUNDLE_ID_LIST, out);
    } forMessageType:SGCMSG_LIST_PUSH_REGISTERED_APPS];

    [gSGCSBServer registerHandler:^(const SGControlChannelMessage *req,
                                    SGControlReplyBlock reply,
                                    SGControlReplyErrorBlock replyError) {
        if (req->payloadLength < sizeof(SGCBundleIdPayload)) {
            replyError(SGCERR_INVALID_REQUEST, @"reset registration payload too short");
            return;
        }
        SGCBundleIdPayload *bp = (SGCBundleIdPayload *)req->payload;
        NSString *bundleId = [[NSString alloc] initWithBytes:bp->bundleID
                                                      length:strnlen(bp->bundleID, sizeof(bp->bundleID))
                                                    encoding:NSUTF8StringEncoding];
        if (!SG_IsIdentifierStringSafe(bundleId)) {
            [bundleId release];
            replyError(SGCERR_INVALID_REQUEST, @"reset registration bundle id invalid");
            return;
        }
        NSString *bidForReset = [bundleId copy];
        dispatch_async(dispatch_get_main_queue(), ^{
            SGN_DeregisterAppNatively(bidForReset);
            [bidForReset release];
        });
        [bundleId release];
        reply(SGCMSG_GENERIC_ACK, nil);
    } forMessageType:SGCMSG_RESET_APP_REGISTRATION];

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
        ScheduleAppDeletion(bundleId);
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            SendDeleteAppToDaemon(bundleId);
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
        ScheduleAppDeletion(bundleId);
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            SendDeleteAppToDaemon(bundleId);
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
- (void)remoteNotificationRegistrationFailedWithError:(NSError *)error;
@end

@interface NSObject (SGNAppExtras)
- (NSString *)bundleIdentifier;
- (SBRemoteApplication *)remoteApplication;
@end

#pragma mark - Native iOS Push Registration State Query

static NSArray *SGN_AllNativelyRegisteredBundles(void) {
    if (SGN_IS_PRE_IOS_9) {
        SBRemoteNotificationServer *server = [%c(SBRemoteNotificationServer) sharedInstance];
        NSDictionary *dict = GetIvar(server, "_bundleIdentifiersToClients");
        if ([dict isKindOfClass:[NSDictionary class]]) return [dict allKeys];
        if ([server respondsToSelector:@selector(_allPushRegisteredThirdPartyBundleIDs)]) {
            return [server _allPushRegisteredThirdPartyBundleIDs] ?: @[];
        }
        return @[];
    }

    id userNS = [NSClassFromString(@"UNUserNotificationServer") performSelector:@selector(sharedInstance)];
    id registrar = GetIvar(userNS, "_registrarConnectionListener");
    id remoteSrv = GetIvar(registrar, "_remoteNotificationServer")
                ?: GetIvar(registrar, "_removeNotificationServer");
    NSDictionary *dict = GetIvar(remoteSrv, "_bundleIdentifiersToClients");
    if (![dict isKindOfClass:[NSDictionary class]]) return @[];
    return [dict allKeys];
}

static BOOL SGN_BundleRegisteredWithNativePush(NSString *bundleId) {
    if (!bundleId.length) return NO;
    return [SGN_AllNativelyRegisteredBundles() containsObject:bundleId];
}

#pragma mark - Native Deregister (swipe-delete = factory reset)

static NSString *sActiveDeregisterBundle = nil;

static BOOL SGN_IsCascadeReEntry(NSString *bundleId) {
    return bundleId.length
        && sActiveDeregisterBundle
        && [sActiveDeregisterBundle isEqualToString:bundleId];
}

static void SGN_DeregisterAppNatively(NSString *bundleId) {
    if (!bundleId.length) return;

    NSString *previousActive = sActiveDeregisterBundle;
    sActiveDeregisterBundle  = [bundleId copy];

    if (SGN_IS_PRE_IOS_9) {
        id app = SBApp_LookupByIdentifier(bundleId);
        SBRemoteNotificationServer *server = [%c(SBRemoteNotificationServer) sharedInstance];
        if (app && [server respondsToSelector:@selector(unregisterApplication:)]) {
            [server unregisterApplication:app];
            NSLog(@"[SGN] Native deregister (classic): %@", bundleId);
        }
        NSMutableDictionary *clientsDict = GetIvar(server, "_bundleIdentifiersToClients");
        if ([clientsDict isKindOfClass:[NSMutableDictionary class]]) {
            [clientsDict removeObjectForKey:bundleId];
        }
        SBApplicationPersistence *persist = [%c(SBApplicationPersistence) sharedInstance];
        if ([persist respondsToSelector:@selector(setArchivedObject:forKey:bundleOrDisplayIdentifier:)]) {
            [persist setArchivedObject:nil
                                forKey:@"SBRemoteNotificationClient"
             bundleOrDisplayIdentifier:bundleId];
        }
    } else {
        id userNS = [NSClassFromString(@"UNUserNotificationServer") performSelector:@selector(sharedInstance)];
        id registrar = GetIvar(userNS, "_registrarConnectionListener");
        SEL sel = @selector(invalidateTokenForRemoteNotificationsForBundleIdentifier:);
        if ([registrar respondsToSelector:sel]) {
            [registrar performSelector:sel withObject:bundleId];
            NSLog(@"[SGN] Native deregister (iOS 9+): %@", bundleId);
        }
    }

    NSString *snapshot = sActiveDeregisterBundle;
    dispatch_async(dispatch_get_main_queue(), ^{
        if (sActiveDeregisterBundle == snapshot) {
            [sActiveDeregisterBundle release];
            sActiveDeregisterBundle = previousActive;
        }
    });
}

#pragma mark - Token Registration

static void SGN_InstallTokenGuard(void);

static void SGN_DeliverSuccess(NSString *bundleId, id application, id environment,
                               int notificationTypes, NSData *token) {
    if (!bundleId.length || !token) return;
    SGN_InstallTokenGuard();

    if (application) {
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
    }

    id remoteApp = SGN_RemoteAppForBundle(bundleId);
    if ([remoteApp respondsToSelector:@selector(remoteNotificationRegistrationSucceededWithDeviceToken:)]) {
        [remoteApp performSelector:@selector(remoteNotificationRegistrationSucceededWithDeviceToken:)
                        withObject:token];
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
        NSMutableDictionary *prefs     = SGN_OwnedPlistAt(kPrefsPlistPath);
        NSMutableDictionary *appStatus = SGN_OwnedMutableDictForKey(prefs, @"appStatus");
        [appStatus setObject:@YES forKey:sPendingBundleId];
        [prefs setObject:appStatus forKey:@"appStatus"];
        [prefs writeToFile:kPrefsPlistPath atomically:YES];
        [appStatus release];
        [prefs release];

        if (sPendingIsModern) {
            SGN_AsyncFetchAndDeliverToken(sPendingBundleId, nil, nil, 0);
        } else {
            SGN_AsyncFetchAndDeliverToken(sPendingBundleId, sPendingApp,
                                          sPendingEnv, sPendingTypes);
        }
    } else {
        NSMutableDictionary *prefs     = SGN_OwnedPlistAt(kPrefsPlistPath);
        NSMutableDictionary *appStatus = SGN_OwnedMutableDictForKey(prefs, @"appStatus");
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
        @"Choose which service should provide its push token. "
        @"iOS may still ask whether to allow alerts and sounds afterwards; "
        @"that permission prompt will not change this provider choice.",
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

    if (SGN_IsCascadeReEntry(bundleId)) {
        NSLog(@"[SGN] Suppressing deregister cascade for %@", bundleId);
        return 0;
    }

    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath];
    id existing = [[prefs objectForKey:@"appStatus"] objectForKey:bundleId];

    if (existing) {
        SGN_InstallTokenGuard();
        SGN_AsyncFetchAndDeliverToken(bundleId, application, environment,
                                      notificationTypes);
        return 1;
    }

    if (SGN_BundleRegisteredWithNativePush(bundleId)) {
        return %orig;
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

    if (SGN_IsCascadeReEntry(bundleIdentifier)) {
        NSLog(@"[SGN] Suppressing deregister cascade for %@", bundleIdentifier);
        %orig;
        return;
    }

    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath];
    NSDictionary *appStatus = [prefs objectForKey:@"appStatus"];
    id existing = [appStatus objectForKey:bundleIdentifier];
    if (existing) {
        SGN_InstallTokenGuard();
        SGN_AsyncFetchAndDeliverToken(bundleIdentifier, nil, nil, 0);
        %orig;
        return;
    }

    if (SGN_BundleRegisteredWithNativePush(bundleIdentifier)) {
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

#import <substrate.h>

static BOOL SGN_IsSkyglowToken(NSData *token) {
    if (!token || token.length < 16) return NO;
    const uint8_t *b = (const uint8_t *)token.bytes;
    return (b[0] >= 0x20 && b[0] <= 0x7E);
}

static NSString *SGN_BundleIdForRemoteAppProxy(id proxy) {
    for (NSString *ivarName in @[@"_application", @"_app", @"_sbApplication"]) {
        id sbApp = GetIvar(proxy, [ivarName UTF8String]);
        if (sbApp && [sbApp respondsToSelector:@selector(bundleIdentifier)]) {
            NSString *bid = [sbApp bundleIdentifier];
            if (bid.length) return bid;
        }
    }
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
        if (existing) {
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
    /* Install subscripting + environ stubs before any Foundation calls.
     * No-op on iOS 6+.  (Also runs via the file's __attribute__((constructor));
     * this explicit call is defensive coverage against constructor ordering.) */
    SGNInstallCompatibilityShim();

    StartSpringBoardControlChannel();
    StartDaemonControlChannelClient();

    /* Status bar dot — lives in SGNStatusBarIndicator.m, subscribes to the
     * daemon's STATE_CHANGED + CONFIG_RELOADED events on the channel we
     * just started, and creates/destroys the libstatusbar item per the
     * customization toggle in prefs. */
    extern void SGNStatusBarIndicator_Start(SGControlChannel *daemonClient);
    SGNStatusBarIndicator_Start(gSGCDaemonClient);

    if (SGN_IS_PRE_IOS_8) {
        %init(HookUninstall_Classic);
    } else {
        %init(HookUninstall_Modern);
    }

    if (SGN_IS_PRE_IOS_9) {
        %init(HookRegistration_Classic);
    } else {
        %init(HookRegistration_iOS9);
    }
}
