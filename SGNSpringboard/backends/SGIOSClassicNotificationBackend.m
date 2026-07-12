#import "SGNNativePushBroker.h"

#import "SGNAppIntent.h"
#import "SGNDaemonBridge.h"
#import "SGNNativePush.h"
#import "SGNPrivateAPI.h"
#import <objc/message.h>

static SBRemoteNotificationServer *SGNClassicServer(void) {
    Class serverClass = NSClassFromString(@"SBRemoteNotificationServer");
    return [serverClass respondsToSelector:@selector(sharedInstance)]
        ? [serverClass sharedInstance] : nil;
}

static NSArray *SGNClassicSafeIdentifiers(SBRemoteNotificationServer *server) {
    id clients = GetIvar(server, "_bundleIdentifiersToClients");
    NSArray *identifiers = [clients isKindOfClass:[NSDictionary class]]
        ? [clients allKeys] : nil;
    if (!identifiers && [server respondsToSelector:
        @selector(_allPushRegisteredThirdPartyBundleIDs)]) {
        identifiers = [server _allPushRegisteredThirdPartyBundleIDs];
    }
    NSMutableArray *safe = [NSMutableArray array];
    for (id candidate in identifiers ?: @[]) {
        if ([candidate isKindOfClass:[NSString class]] &&
            SG_IsIdentifierStringSafe(candidate)) {
            [safe addObject:candidate];
        }
    }
    [safe sortUsingSelector:@selector(compare:)];
    return safe;
}

@interface SGIOSClassicNotificationBackend : NSObject <SGNotificationBackend>
@end

@implementation SGIOSClassicNotificationBackend

+ (BOOL)isSupported {
    return SGNClassicServer() != nil;
}

- (NSArray *)registeredBundleIdentifiersWithError:(SGControlError *)error
                                             detail:(NSString **)detail {
    SBRemoteNotificationServer *server = SGNClassicServer();
    if (!server) {
        if (error) *error = SGCERR_UNSUPPORTED;
        if (detail) *detail = @"classic notification server unavailable";
        return nil;
    }
    if (error) *error = SGCERR_OK;
    if (detail) *detail = nil;
    return SGNClassicSafeIdentifiers(server);
}

- (void)registerBundleIdentifier:(NSString *)bundleIdentifier
                       completion:(SGNNativePushBrokerCompletion)completion {
    if (!SG_IsIdentifierStringSafe(bundleIdentifier)) {
        if (completion) completion(SGCERR_INVALID_REQUEST, @"bundle id invalid");
        return;
    }
    id application = SBApp_LookupByIdentifier(bundleIdentifier);
    SBRemoteNotificationServer *server = SGNClassicServer();
    if (!application || !server) {
        if (completion) completion(SGCERR_NOT_FOUND, @"application not found");
        return;
    }
    @try {
        SGNRegistrationBeginPassThrough();
        [server registerApplication:application
                     forEnvironment:@"production"
                          withTypes:7];
        SGNRegistrationEndPassThrough();
        if (completion) completion(SGCERR_OK, nil);
    } @catch (NSException *exception) {
        SGNRegistrationEndPassThrough();
        if (completion) completion(SGCERR_INTERNAL,
            [exception reason] ?: @"classic registration exception");
    }
}

- (SGControlError)beginAuthorizationForBundleIdentifier:
    (NSString *)bundleIdentifier detail:(NSString **)detail {
    if (!SG_IsIdentifierStringSafe(bundleIdentifier)) {
        if (detail) *detail = @"bundle id invalid";
        return SGCERR_INVALID_REQUEST;
    }
    if (detail) *detail = @"classic authorization is part of registration";
    return SGCERR_UNSUPPORTED;
}

- (void)resetBundleIdentifier:(NSString *)bundleIdentifier
                    completion:(SGNNativePushBrokerCompletion)completion {
    if (!SG_IsIdentifierStringSafe(bundleIdentifier)) {
        if (completion) completion(SGCERR_INVALID_REQUEST, @"bundle id invalid");
        return;
    }
    id application = SBApp_LookupByIdentifier(bundleIdentifier);
    SBRemoteNotificationServer *server = SGNClassicServer();
    if (!server) {
        if (completion) completion(SGCERR_UNSUPPORTED,
                                   @"classic notification server unavailable");
        return;
    }
    @try {
        if (application && [server respondsToSelector:
            @selector(unregisterApplication:)]) {
            [server unregisterApplication:application];
        }
        id clients = GetIvar(server, "_bundleIdentifiersToClients");
        if ([clients isKindOfClass:[NSMutableDictionary class]]) {
            [clients removeObjectForKey:bundleIdentifier];
        }
        SBApplicationPersistence *persistence =
            [NSClassFromString(@"SBApplicationPersistence") sharedInstance];
        if ([persistence respondsToSelector:
            @selector(setArchivedObject:forKey:bundleOrDisplayIdentifier:)]) {
            [persistence setArchivedObject:nil
                                    forKey:@"SBRemoteNotificationClient"
                 bundleOrDisplayIdentifier:bundleIdentifier];
        }
        if (completion) completion(SGCERR_OK, nil);
    } @catch (NSException *exception) {
        if (completion) completion(SGCERR_INTERNAL,
            [exception reason] ?: @"classic reset exception");
    }
}

- (void)deliverAPNSPayload:(NSDictionary *)payload
        toBundleIdentifier:(NSString *)bundleIdentifier
                completion:(SGNNativePushBrokerCompletion)completion {
    if (!SG_IsIdentifierStringSafe(bundleIdentifier) ||
        ![payload isKindOfClass:[NSDictionary class]]) {
        if (completion) completion(SGCERR_INVALID_REQUEST,
                                   @"classic delivery input invalid");
        return;
    }
    id server = SGNClassicServer();
    if (!server) {
        if (completion) completion(SGCERR_UNSUPPORTED,
                                   @"classic push receiver unavailable");
        return;
    }

    @try {
        SEL incomingSelector =
            @selector(connection:didReceiveIncomingMessage:);
        if ([server respondsToSelector:incomingSelector]) {
            APSIncomingMessage *message =
                [[NSClassFromString(@"APSIncomingMessage") alloc]
                    initWithTopic:bundleIdentifier userInfo:payload];
            if (!message) {
                if (completion) completion(SGCERR_UNSUPPORTED,
                                           @"classic APS message unavailable");
                return;
            }
            [server connection:nil didReceiveIncomingMessage:message];
            [message release];
        } else {
            SEL oldSelector =
                @selector(connection:didReceiveMessageForTopic:userInfo:);
            if (![server respondsToSelector:oldSelector]) {
                if (completion) completion(SGCERR_UNSUPPORTED,
                                           @"classic push selector unavailable");
                return;
            }
            void (*send)(id, SEL, id, id, id) =
                (void (*)(id, SEL, id, id, id))objc_msgSend;
            send(server, oldSelector, nil, bundleIdentifier, payload);
        }
        if (completion) completion(SGCERR_OK, nil);
    } @catch (NSException *exception) {
        if (completion) completion(SGCERR_INTERNAL,
            [exception reason] ?: @"classic delivery exception");
    }
}

- (void)activateSkyglowForBundleIdentifier:(NSString *)bundleIdentifier
                                completion:(SGNNativePushBrokerCompletion)completion {
    if (!SG_IsIdentifierStringSafe(bundleIdentifier)) {
        if (completion) completion(SGCERR_INVALID_REQUEST, @"bundle id invalid");
        return;
    }
    id application = SBApp_LookupByIdentifier(bundleIdentifier);
    SBRemoteNotificationServer *server = SGNClassicServer();
    if (!application || !server) {
        if (completion) completion(SGCERR_NOT_FOUND, @"application not found");
        return;
    }
    /* Token delivery creates the classic notification client and presents the
     * legacy permission alert, without manufacturing an Apple registration. */
    SGN_AsyncFetchAndDeliverToken(bundleIdentifier, application,
                                  @"production", 7, completion);
}

@end
