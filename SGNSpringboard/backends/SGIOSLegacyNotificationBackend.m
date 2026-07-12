#import "SGNNativePushBroker.h"

#import "SGNAppIntent.h"
#import "SGNDaemonBridge.h"
#import "SGNNativePush.h"
#import "SGNPrivateAPI.h"

static id SGNLegacyRegistrar(void) {
    Class serverClass = NSClassFromString(@"UNUserNotificationServer");
    id server = [serverClass respondsToSelector:@selector(sharedInstance)]
        ? [serverClass sharedInstance] : nil;
    return GetIvar(server, "_registrarConnectionListener");
}

static id SGNLegacyRemoteNotificationServer(void) {
    return GetIvar(SGNLegacyRegistrar(), "_remoteNotificationServer");
}

static NSArray *SGNLegacySafeIdentifiers(id remoteServer) {
    id clients = GetIvar(remoteServer, "_bundleIdentifiersToClients");
    NSArray *identifiers = [clients isKindOfClass:[NSDictionary class]]
        ? [clients allKeys] : nil;
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

@interface SGIOSLegacyNotificationBackend : NSObject <SGNotificationBackend>
@end

@implementation SGIOSLegacyNotificationBackend

+ (BOOL)isSupported {
    id registrar = SGNLegacyRegistrar();
    id remoteServer = GetIvar(registrar, "_remoteNotificationServer");
    return registrar && remoteServer &&
        [registrar respondsToSelector:
            @selector(requestTokenForRemoteNotificationsForBundleIdentifier:
                      withResult:)] &&
        [remoteServer respondsToSelector:
            @selector(connection:didReceiveIncomingMessage:)];
}

- (NSArray *)registeredBundleIdentifiersWithError:(SGControlError *)error
                                             detail:(NSString **)detail {
    id remoteServer = SGNLegacyRemoteNotificationServer();
    if (!remoteServer) {
        if (error) *error = SGCERR_UNSUPPORTED;
        if (detail) *detail = @"legacy notification server unavailable";
        return nil;
    }
    if (error) *error = SGCERR_OK;
    if (detail) *detail = nil;
    return SGNLegacySafeIdentifiers(remoteServer);
}

- (void)registerBundleIdentifier:(NSString *)bundleIdentifier
                       completion:(SGNNativePushBrokerCompletion)completion {
    if (!SG_IsIdentifierStringSafe(bundleIdentifier)) {
        if (completion) completion(SGCERR_INVALID_REQUEST, @"bundle id invalid");
        return;
    }
    id registrar = SGNLegacyRegistrar();
    if (!registrar) {
        if (completion) completion(SGCERR_UNSUPPORTED,
                                   @"legacy native registrar unavailable");
        return;
    }
    if (!SBApp_LookupByIdentifier(bundleIdentifier)) {
        if (completion) completion(SGCERR_NOT_FOUND,
                                   @"application not found");
        return;
    }

    @try {
        SGNRegistrationBeginPassThrough();
        [registrar
            requestTokenForRemoteNotificationsForBundleIdentifier:
                bundleIdentifier
            withResult:^(id result, id error) {
                (void)result;
                (void)error;
            }];
        SGNRegistrationEndPassThrough();
        if (completion) completion(SGCERR_OK, nil);
    } @catch (NSException *exception) {
        SGNRegistrationEndPassThrough();
        if (completion) completion(SGCERR_INTERNAL,
            [exception reason] ?: @"legacy registration exception");
    }
}

- (SGControlError)beginAuthorizationForBundleIdentifier:
    (NSString *)bundleIdentifier detail:(NSString **)detail {
    if (!SG_IsIdentifierStringSafe(bundleIdentifier)) {
        if (detail) *detail = @"bundle id invalid";
        return SGCERR_INVALID_REQUEST;
    }
    if (detail) *detail = @"separate authorization is unavailable on this iOS version";
    return SGCERR_UNSUPPORTED;
}

- (void)resetBundleIdentifier:(NSString *)bundleIdentifier
                    completion:(SGNNativePushBrokerCompletion)completion {
    if (!SG_IsIdentifierStringSafe(bundleIdentifier)) {
        if (completion) completion(SGCERR_INVALID_REQUEST, @"bundle id invalid");
        return;
    }
    id registrar = SGNLegacyRegistrar();
    if (![registrar respondsToSelector:
        @selector(invalidateTokenForRemoteNotificationsForBundleIdentifier:)]) {
        if (completion) completion(SGCERR_UNSUPPORTED,
                                   @"legacy native reset unavailable");
        return;
    }
    @try {
        [registrar invalidateTokenForRemoteNotificationsForBundleIdentifier:
            bundleIdentifier];
        if (completion) completion(SGCERR_OK, nil);
    } @catch (NSException *exception) {
        if (completion) completion(SGCERR_INTERNAL,
            [exception reason] ?: @"legacy reset exception");
    }
}

- (void)deliverAPNSPayload:(NSDictionary *)payload
        toBundleIdentifier:(NSString *)bundleIdentifier
                completion:(SGNNativePushBrokerCompletion)completion {
    if (!SG_IsIdentifierStringSafe(bundleIdentifier) ||
        ![payload isKindOfClass:[NSDictionary class]]) {
        if (completion) completion(SGCERR_INVALID_REQUEST,
                                   @"legacy delivery input invalid");
        return;
    }
    id remoteServer = SGNLegacyRemoteNotificationServer();
    APSIncomingMessage *message = [[NSClassFromString(@"APSIncomingMessage") alloc]
        initWithTopic:bundleIdentifier userInfo:payload];
    if (!remoteServer || !message) {
        [message release];
        if (completion) completion(SGCERR_UNSUPPORTED,
                                   @"legacy push receiver unavailable");
        return;
    }
    @try {
        [remoteServer connection:nil didReceiveIncomingMessage:message];
        if (completion) completion(SGCERR_OK, nil);
    } @catch (NSException *exception) {
        if (completion) completion(SGCERR_INTERNAL,
            [exception reason] ?: @"legacy delivery exception");
    }
    [message release];
}

- (void)activateSkyglowForBundleIdentifier:(NSString *)bundleIdentifier
                                completion:(SGNNativePushBrokerCompletion)completion {
    if (!SG_IsIdentifierStringSafe(bundleIdentifier)) {
        if (completion) completion(SGCERR_INVALID_REQUEST, @"bundle id invalid");
        return;
    }
    if (!SBApp_LookupByIdentifier(bundleIdentifier)) {
        if (completion) completion(SGCERR_NOT_FOUND, @"application not found");
        return;
    }
    SGN_AsyncFetchAndDeliverToken(bundleIdentifier, nil, nil, 0, completion);
}

@end
