#import "SGNNativePush.h"
#import "SGNPrivateAPI.h"
#import "SGNAppIntent.h"
#import "SGNDaemonBridge.h"
#import "SGSharedConstants.h"
#import "SGDurableInbox.h"
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <substrate.h>

#pragma mark - Native iOS Push Registration State Query

NSArray *SGN_AllNativelyRegisteredBundles(void) {
    if (SGN_IS_PRE_IOS_9) {
        SBRemoteNotificationServer *server = [objc_getClass("SBRemoteNotificationServer") sharedInstance];
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

BOOL SGN_BundleRegisteredWithNativePush(NSString *bundleId) {
    if (!bundleId.length) return NO;
    return [SGN_AllNativelyRegisteredBundles() containsObject:bundleId];
}

#pragma mark - Native Deregister (swipe-delete = factory reset)

static NSString *sActiveDeregisterBundle = nil;
static NSUInteger sDeregisterGeneration = 0;

BOOL SGN_IsCascadeReEntry(NSString *bundleId) {
    return bundleId.length
        && sActiveDeregisterBundle
        && [sActiveDeregisterBundle isEqualToString:bundleId];
}

void SGN_DeregisterAppNatively(NSString *bundleId) {
    if (!bundleId.length) return;
    SGNClearRuntimeAppIntent(bundleId);

    [sActiveDeregisterBundle release];
    sActiveDeregisterBundle = [bundleId copy];
    NSUInteger gen = ++sDeregisterGeneration;

    if (SGN_IS_PRE_IOS_9) {
        id app = SBApp_LookupByIdentifier(bundleId);
        SBRemoteNotificationServer *server = [objc_getClass("SBRemoteNotificationServer") sharedInstance];
        if (app && [server respondsToSelector:@selector(unregisterApplication:)]) {
            [server unregisterApplication:app];
            NSLog(@"[SGN] Native deregister (classic): %@", bundleId);
        }
        NSMutableDictionary *clientsDict = GetIvar(server, "_bundleIdentifiersToClients");
        if ([clientsDict isKindOfClass:[NSMutableDictionary class]]) {
            [clientsDict removeObjectForKey:bundleId];
        }
        SBApplicationPersistence *persist = [objc_getClass("SBApplicationPersistence") sharedInstance];
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

void SGN_DeliverSuccess(NSString *bundleId, id application, id environment,
                        int notificationTypes, NSData *token) {
    if (!bundleId.length || !token) return;
    SGN_InstallTokenGuard();

    if (application) {
        SBRemoteNotificationServer *server = [objc_getClass("SBRemoteNotificationServer") sharedInstance];
        NSMutableDictionary *clientsDict = [server valueForKey:@"_bundleIdentifiersToClients"];
        SBRemoteNotificationClient *client = clientsDict[bundleId];
        BOOL needsPersist = NO;
        if (!client) {
            client = [[[objc_getClass("SBRemoteNotificationClient") alloc] initWithBundleIdentifier:bundleId] autorelease];
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

            Class alertCls = objc_getClass("SBRemoteNotificationPermissionAlert");
            SBRemoteNotificationPermissionAlert *alert = nil;
            if ([alertCls instancesRespondToSelector:@selector(initWithApplication:notificationTypes:)]) {
                alert = [[alertCls alloc] initWithApplication:application notificationTypes:alertTypes];
            } else if ([alertCls instancesRespondToSelector:@selector(initWithApplication:)]) {
                alert = [[alertCls alloc] performSelector:@selector(initWithApplication:) withObject:application];
            }
            if (alert) {
                SBAlertItemsController *ctrl = [objc_getClass("SBAlertItemsController") sharedInstance];
                [ctrl deactivateAlertItemsOfClass:alertCls];
                [ctrl activateAlertItem:alert];
                [client setSettingsPresentedTypes:settingsPresentedTypes | requestedTypes];
                [alert release];
            }
        }

        if (needsPersist) {
            [[objc_getClass("SBApplicationPersistence") sharedInstance]
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

#pragma mark - Registration Choice Prompt

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

BOOL SGNRegistrationConsumePassThrough(void) {
    if (sPassThrough) {
        sPassThrough = NO;
        return YES;
    }
    return NO;
}

void SGNRegistrationPresentClassicChoice(id server, id application,
                                         id environment, NSString *bundleId,
                                         int notificationTypes) {
    if (sPendingBundleId) {
        NSLog(@"[SGN] Choice alert already pending for %@; deferring %@", sPendingBundleId, bundleId);
        return;
    }
    NSLog(@"[SGN] Classic hook: showing choice alert for %@", bundleId);
    [sPendingServer release];   sPendingServer = [server retain];
    [sPendingApp release];      sPendingApp = [application retain];
    [sPendingEnv release];      sPendingEnv = [environment retain];
    [sPendingBundleId release]; sPendingBundleId = [bundleId copy];
    sPendingTypes = notificationTypes;
    sPendingIsModern = NO;

    ShowRegistrationChoiceAlert(bundleId);
}

void SGNRegistrationPresentModernChoice(id server, NSString *bundleId,
                                        id resultBlock) {
    NSString *bidCopy = [bundleId copy];
    id resultCopy = [resultBlock copy];
    id serverCopy = [server retain];
    dispatch_async(dispatch_get_main_queue(), ^{
        if (sPendingBundleId) {
            NSLog(@"[SGN] Choice alert already pending for %@; deferring %@", sPendingBundleId, bidCopy);
        } else {
            [sPendingServer release];      sPendingServer = [serverCopy retain];
            [sPendingBundleId release];    sPendingBundleId = [bidCopy copy];
            [sPendingResultBlock release]; sPendingResultBlock = [resultCopy copy];
            sPendingIsModern = YES;
            ShowRegistrationChoiceAlert(bidCopy);
        }
        [serverCopy release];
        [bidCopy release];
        [resultCopy release];
    });
}

#pragma mark - Token Guard (drop a late real-APNS token for a Skyglow-owned app)

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

void SGN_InstallTokenGuard(void) {
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
