#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <bootstrap.h>
#import "SGControlChannel.h"
#import "SGControlChannelProtocol.h"
#import "SGSharedConstants.h"
#import "SGDurableInbox.h"
#import "SGCompatibilityShim.h"

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

static NSString *SGNPath(NSString *path) {
    static int rootless = -1;
    if (rootless < 0) {
        rootless = [[NSFileManager defaultManager]
            fileExistsAtPath:@"/var/jb"] ? 1 : 0;
    }
    return rootless ? [@"/var/jb" stringByAppendingString:path] : path;
}

#define kPrefsPlistPath SGNPath(SG_PREFS_PLIST_PATH)

static SGControlChannel *gSGCDaemonClient = nil;
static SGControlChannel *gSGCSBServer     = nil;
static NSMutableDictionary *gSGNRuntimeAppIntent = nil;

static NSObject *SGNRuntimeIntentLock(void) {
    static NSObject *lock = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        lock = [[NSObject alloc] init];
    });
    return lock;
}

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

/* SpringBoard must honor a provider choice immediately, even if live daemon IPC
 * has not reached the daemon-owned plist yet.
 * NSNull means "Apple/no Skyglow intent"; any NSNumber means Skyglow owns the
 * registration. The overlay disappears lazily once the daemon-owned plist
 * reflects the same intent. */
static void SGNSetRuntimeAppIntent(NSString *bundleId, BOOL usesSkyglow) {
    if (!bundleId.length) return;
    @synchronized(SGNRuntimeIntentLock()) {
        if (!gSGNRuntimeAppIntent) {
            gSGNRuntimeAppIntent = [[NSMutableDictionary alloc] init];
        }
        [gSGNRuntimeAppIntent setObject:(usesSkyglow ? (id)@YES : (id)[NSNull null])
                                forKey:bundleId];
    }
}

static void SGNClearRuntimeAppIntent(NSString *bundleId) {
    if (!bundleId.length) return;
    @synchronized(SGNRuntimeIntentLock()) {
        [gSGNRuntimeAppIntent removeObjectForKey:bundleId];
    }
}

static id SGNEffectiveAppIntent(NSString *bundleId) {
    if (!bundleId.length) return nil;
    NSDictionary *prefs =
        [NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath];
    id persisted = [[prefs objectForKey:@"appStatus"] objectForKey:bundleId];

    id runtime = nil;
    @synchronized(SGNRuntimeIntentLock()) {
        runtime = [[gSGNRuntimeAppIntent objectForKey:bundleId] retain];
    }
    if (!runtime) return persisted;

    BOOL runtimeUsesSkyglow = (runtime != [NSNull null]);
    BOOL diskMatches = runtimeUsesSkyglow ? (persisted != nil)
                                         : (persisted == nil);
    if (diskMatches) {
        SGNClearRuntimeAppIntent(bundleId);
        [runtime release];
        return persisted;
    }

    if (!runtimeUsesSkyglow) {
        [runtime release];
        return nil;
    }
    return [runtime autorelease];
}

#pragma mark - Daemon Communication (SGControlChannel client)

static void SGNSendBundleCommand(SGControlMessageType messageType,
                                 NSString *bundleId,
                                 NSString *inboxEventPathToRemove) {
    if (!bundleId.length) return;
    if (!gSGCDaemonClient) return;

    SGCBundleIdPayload payload;
    memset(&payload, 0, sizeof(payload));
    SGNCopyCString(payload.bundleID, sizeof(payload.bundleID), [bundleId UTF8String]);

    NSString *eventPathCopy = [inboxEventPathToRemove copy];
    [gSGCDaemonClient sendRequest:messageType
                          payload:[NSData dataWithBytes:&payload length:sizeof(payload)]
                          timeout:SG_CONTROL_DELETE_APP_TIMEOUT_SEC
                       completion:^(SGControlError error,
                                    const SGControlChannelMessage *response) {
        if (error == SGCERR_OK && eventPathCopy) {
            NSDictionary *event = [NSDictionary dictionaryWithObject:eventPathCopy
                forKey:SGDurableEventFilePathKey];
            if (!SGDurableEventRemove(event)) {
                NSLog(@"[SGN] Applied uninstall but could not remove inbox event %@",
                      [eventPathCopy lastPathComponent]);
            }
        }
        [eventPathCopy release];
    }];
}

static void SGNSendDeleteAppCommand(NSString *bundleId) {
    if (!bundleId.length) return;
    SGNSetRuntimeAppIntent(bundleId, NO);

    NSError *enqueueError = nil;
    NSString *eventPath = SGDurableEventEnqueueDeleteApp(
        SGNPath(SG_DURABLE_EVENT_INBOX_PATH),
        bundleId, &enqueueError);
    if (!eventPath) {
        /* The daemon owns persistent app state.  If the missed-uninstall inbox
         * cannot be recorded, still try live IPC, but do not mutate the daemon
         * prefs plist from SpringBoard. */
        NSLog(@"[SGN] Durable uninstall enqueue failed for %@: %@; continuing with live IPC only",
              bundleId, enqueueError);
    }

    SGNSendBundleCommand(SGCMSG_DELETE_APP, bundleId, eventPath);
}

static NSSet *SGNMissingPersistedApplications(void) {
    SBApplicationController *controller =
        [%c(SBApplicationController) sharedInstance];
    BOOL lookupAvailable =
        [controller respondsToSelector:@selector(applicationWithBundleIdentifier:)] ||
        [controller respondsToSelector:@selector(applicationWithDisplayIdentifier:)];
    if (!controller || !lookupAvailable) return nil;

    NSDictionary *preferences =
        [NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath];
    NSDictionary *appStatus = [preferences objectForKey:@"appStatus"];
    if (![appStatus isKindOfClass:[NSDictionary class]]) return [NSSet set];

    NSMutableSet *missing = [NSMutableSet set];
    for (id bundleId in appStatus) {
        if (![bundleId isKindOfClass:[NSString class]] ||
            !SG_IsIdentifierStringSafe(bundleId)) {
            continue;
        }
        if (!SBApp_LookupByIdentifier(bundleId)) {
            [missing addObject:bundleId];
        }
    }
    return missing;
}

static void SGNScheduleInstalledApplicationReconciliation(void) {
    /* Do not infer an uninstall from SpringBoard's partially populated startup
     * model. Two main-thread probes, separated by ten seconds, must agree.
     * This recovers an uninstall hook that never fired while keeping all
     * platform inventory knowledge inside the SpringBoard adapter. */
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10ull * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        NSSet *firstPass = [SGNMissingPersistedApplications() copy];
        if (!firstPass) {
            NSLog(@"[SGN] Installed-application reconciliation unavailable on this OS");
            return;
        }
        if ([firstPass count] == 0) {
            [firstPass release];
            return;
        }

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10ull * NSEC_PER_SEC),
                       dispatch_get_main_queue(), ^{
            NSSet *secondPass = SGNMissingPersistedApplications();
            if (secondPass) {
                for (NSString *bundleId in firstPass) {
                    if (![secondPass containsObject:bundleId]) continue;
                    NSLog(@"[SGN] Recovering missed uninstall for %@", bundleId);
                    SGNSendDeleteAppCommand(bundleId);
                }
            }
            [firstPass release];
        });
    });
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
    if (flat[@"sound"])    [aps setObject:flat[@"sound"] forKey:@"sound"];
    if (flat[@"badge"])    [aps setObject:flat[@"badge"] forKey:@"badge"];
    if (flat[@"category"]) [aps setObject:flat[@"category"] forKey:@"category"];
    id contentAvailable = flat[@"content-available"] ?: flat[@"content_available"];
    if (contentAvailable) [aps setObject:contentAvailable forKey:@"content-available"];

    NSMutableDictionary *result = [NSMutableDictionary dictionaryWithObject:aps forKey:@"aps"];
    for (id key in flat) {
        if (![key isKindOfClass:[NSString class]]) continue;
        if ([key isEqualToString:@"title"] || [key isEqualToString:@"body"] ||
            [key isEqualToString:@"sound"] || [key isEqualToString:@"badge"] ||
            [key isEqualToString:@"category"] || [key isEqualToString:@"aps"] ||
            [key isEqualToString:@"content-available"] ||
            [key isEqualToString:@"content_available"]) continue;
        [result setObject:flat[key] forKey:key];
    }
    return result;
}

// Returns YES only when a delivery target existed and the message was handed, NO means nowhere to deliver right now
static BOOL DeliverNotification(NSString *topic, NSDictionary *userInfo) {
    if (!topic.length) return NO;
    NSDictionary *apnsPayload = WrapInAPNSFormat(userInfo ?: @{});

    if (SGN_IS_PRE_IOS_6) {
        id server = [NSClassFromString(@"SBRemoteNotificationServer") performSelector:@selector(sharedInstance)];
        if (!server) return NO;
        SEL sel = @selector(connection:didReceiveMessageForTopic:userInfo:);
        void (*send)(id, SEL, id, id, id) = (void (*)(id, SEL, id, id, id))objc_msgSend;
        send(server, sel, nil, topic, apnsPayload);
        return YES;
    } else if (SGN_IS_PRE_IOS_9) {
        id server = [NSClassFromString(@"SBRemoteNotificationServer") performSelector:@selector(sharedInstance)];
        APSIncomingMessage *msg = [[NSClassFromString(@"APSIncomingMessage") alloc] initWithTopic:topic userInfo:apnsPayload];
        if (!server || !msg) {
            [msg release];
            return NO;
        }
        [server performSelector:@selector(connection:didReceiveIncomingMessage:) withObject:nil withObject:msg];
        [msg release];
        return YES;
    } else {
        APSIncomingMessage *msg = [[NSClassFromString(@"APSIncomingMessage") alloc] initWithTopic:topic userInfo:apnsPayload];
        id userNS = [NSClassFromString(@"UNUserNotificationServer") performSelector:@selector(sharedInstance)];
        id registrar = GetIvar(userNS, "_registrarConnectionListener");
        id remoteSrv = GetIvar(registrar, "_remoteNotificationServer") ?: GetIvar(registrar, "_removeNotificationServer");
        BOOL delivered = NO;
        if (msg && [remoteSrv respondsToSelector:@selector(connection:didReceiveIncomingMessage:)]) {
            [remoteSrv performSelector:@selector(connection:didReceiveIncomingMessage:) withObject:nil withObject:msg];
            delivered = YES;
        }
        [msg release];
        return delivered;
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
        if (pd->userInfoLength > SG_CONTROL_MAX_USERINFO_SIZE) {
            [topic release];
            replyError(SGCERR_INVALID_REQUEST, @"push delivery userInfo too large");
            return;
        }
        if (pd->userInfoLength > 0) {
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
            // Parse failure or a non-dictionary root means the payload was damaged in transit
            if (![userInfo isKindOfClass:[NSDictionary class]]) {
                [topic release];
                replyError(SGCERR_INVALID_REQUEST, @"push delivery userInfo not a plist dictionary");
                return;
            }
        }

        SGControlReplyBlock      replyCopy      = [reply copy];
        SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
        NSDictionary            *userInfoRet    = [userInfo retain];

        dispatch_async(dispatch_get_main_queue(), ^{
            BOOL ok = YES;
            NSString *failReason = nil;
            @try {
                NSLog(@"[SGN] Delivering push for topic: %@", topic);
                ok = DeliverNotification(topic, userInfoRet);
                if (!ok) failReason = @"no delivery target (push server not available yet)";
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
        SGControlReplyBlock replyCopy = [reply copy];
        dispatch_async(dispatch_get_main_queue(), ^{
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

            replyCopy(SGCMSG_BUNDLE_ID_LIST, out);
            [replyCopy release];
        });
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
    NSString *bundleId = nil;
    if ([(id)self respondsToSelector:@selector(bundleIdentifier)]) {
        bundleId = [(id)self performSelector:@selector(bundleIdentifier)];
    } else {
        @try { bundleId = [(id)self valueForKey:@"_bundleIdentifier"]; }
        @catch (NSException *e) { bundleId = nil; }
    }
    if (bundleId.length) {
        SGNSendDeleteAppCommand(bundleId);
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
        SGNSendDeleteAppCommand(bundleId);
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

static NSUInteger sDeregisterGeneration = 0;

static void SGN_DeregisterAppNatively(NSString *bundleId) {
    if (!bundleId.length) return;
    SGNClearRuntimeAppIntent(bundleId);

    [sActiveDeregisterBundle release];
    sActiveDeregisterBundle = [bundleId copy];
    NSUInteger gen = ++sDeregisterGeneration;

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

    dispatch_async(dispatch_get_main_queue(), ^{
        if (sDeregisterGeneration == gen) {
            [sActiveDeregisterBundle release];
            sActiveDeregisterBundle = nil;
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
            client = [[[%c(SBRemoteNotificationClient) alloc] initWithBundleIdentifier:bundleId] autorelease];
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
            /* The permission alert's initializer is version-specific.  iOS 5/6
             * use -initWithApplication:notificationTypes:; iOS 4.3.x's
             * SBRemoteNotificationPermissionAlert does not implement it and
             * raised an unrecognized-selector that crashed SpringBoard.  Probe
             * for the modern two-arg form, fall back to the legacy one-arg
             * -initWithApplication:, and if neither exists skip the prompt
             * entirely — token delivery below still proceeds regardless. */
            Class alertCls = %c(SBRemoteNotificationPermissionAlert);
            SBRemoteNotificationPermissionAlert *alert = nil;
            if ([alertCls instancesRespondToSelector:@selector(initWithApplication:notificationTypes:)]) {
                alert = [[alertCls alloc] initWithApplication:application notificationTypes:alertTypes];
            } else if ([alertCls instancesRespondToSelector:@selector(initWithApplication:)]) {
                alert = [[alertCls alloc] performSelector:@selector(initWithApplication:) withObject:application];
            }
            if (alert) {
                SBAlertItemsController *ctrl = [%c(SBAlertItemsController) sharedInstance];
                [ctrl deactivateAlertItemsOfClass:alertCls];
                [ctrl activateAlertItem:alert];
                [client setSettingsPresentedTypes:settingsPresentedTypes | requestedTypes];
                [alert release];
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
    if (!sPendingBundleId) return;

    if (buttonIndex == 1) {
        SGNSetRuntimeAppIntent(sPendingBundleId, YES);
        NSUInteger purgedEvents = SGDurableEventPurgeForBundleIdentifier(
            SGNPath(SG_DURABLE_EVENT_INBOX_PATH), sPendingBundleId);
        if (purgedEvents > 0) {
            NSLog(@"[SGN] Purged %lu stale uninstall record(s) for %@ before re-enabling",
                  (unsigned long)purgedEvents, sPendingBundleId);
        }
        SGNSendBundleCommand(SGCMSG_ENABLE_APP,
                             sPendingBundleId,
                             nil);

        if (sPendingIsModern) {
            SGN_AsyncFetchAndDeliverToken(sPendingBundleId, nil, nil, 0);
        } else {
            SGN_AsyncFetchAndDeliverToken(sPendingBundleId, sPendingApp,
                                          sPendingEnv, sPendingTypes);
        }
    } else {
        SGNSetRuntimeAppIntent(sPendingBundleId, NO);
        SGNSendBundleCommand(SGCMSG_CLEAR_APP_INTENT,
                             sPendingBundleId,
                             nil);

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

    id existing = SGNEffectiveAppIntent(bundleId);

    if (existing) {
        SGN_InstallTokenGuard();
        SGN_AsyncFetchAndDeliverToken(bundleId, application, environment,
                                      notificationTypes);
        return 1;
    }

    if (SGN_BundleRegisteredWithNativePush(bundleId)) {
        return %orig;
    }

    if (sPendingBundleId) {
        NSLog(@"[SGN] Choice alert already pending for %@; deferring %@", sPendingBundleId, bundleId);
        return 0;
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

    id existing = SGNEffectiveAppIntent(bundleIdentifier);
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

    NSString *bidCopy = [bundleIdentifier copy];
    id resultCopy = [resultBlock copy];
    dispatch_async(dispatch_get_main_queue(), ^{
        if (sPendingBundleId) {
            NSLog(@"[SGN] Choice alert already pending for %@; deferring %@", sPendingBundleId, bidCopy);
        } else {
            [sPendingServer release];      sPendingServer = [self retain];
            [sPendingBundleId release];    sPendingBundleId = [bidCopy copy];
            [sPendingResultBlock release]; sPendingResultBlock = [resultCopy copy];
            sPendingIsModern = YES;
            ShowRegistrationChoiceAlert(bidCopy);
        }
        [bidCopy release];
        [resultCopy release];
    });
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
        id existing = SGNEffectiveAppIntent(bundleId);
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
    SGNInstallCompatibilityShim();

    StartSpringBoardControlChannel();
    StartDaemonControlChannelClient();
    SGNScheduleInstalledApplicationReconciliation();

    //extern void SGNStatusBarIndicator_Start(SGControlChannel *daemonClient);
    //SGNStatusBarIndicator_Start(gSGCDaemonClient);

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
