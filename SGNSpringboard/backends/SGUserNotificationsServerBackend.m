#import "SGNotificationBackend.h"

#import "SGNAppIntent.h"
#import "SGNDaemonBridge.h"
#import "SGNNativePush.h"
#import "SGNPrivateAPI.h"

static id SGNLegacyUserNotificationServer(void) {
    Class serverClass = NSClassFromString(@"UNUserNotificationServer");
    id server = [serverClass respondsToSelector:@selector(sharedInstance)]
        ? [serverClass sharedInstance] : nil;
    if (server) return server;

    /* iOS 10 moved the same responsibility to the UNS-prefixed server. */
    serverClass = NSClassFromString(@"UNSUserNotificationServer");
    return [serverClass respondsToSelector:@selector(sharedInstance)]
        ? [serverClass sharedInstance] : nil;
}

static id SGNLegacyRegistrar(void) {
    id server = SGNLegacyUserNotificationServer();
    id registrar = GetIvar(server, "_registrarConnectionListener");
    if (!registrar) {
        registrar = GetIvar(server, "_userNotificationServerConnectionListener");
    }
    return registrar;
}

static id SGNLegacyRemoteNotificationServer(void) {
    id registrar = SGNLegacyRegistrar();
    id remoteServer = GetIvar(registrar, "_remoteNotificationServer");
    if (!remoteServer) {
        remoteServer = GetIvar(registrar, "_remoteNotificationService");
    }
    return remoteServer;
}

/* The system's OWN description for a bundle, or nil if it has never been
 * registered as a notification source. */
static id SGNLegacyRegisteredSourceDescription(NSString *bundleIdentifier) {
    id map = GetIvar(SGNLegacyRegistrar(), "_bundleIdentifierToSourceDescription");
    id source = [map isKindOfClass:[NSDictionary class]]
        ? [map objectForKey:bundleIdentifier] : nil;
    if (source) return source;

    map = GetIvar(SGNLegacyRemoteNotificationServer(), "_bundleIdentifiersToDescriptions");
    return [map isKindOfClass:[NSDictionary class]]
        ? [map objectForKey:bundleIdentifier] : nil;
}

/* Apple registers an app as a notification source at install time:
 * LSApplicationWorkspace -> applicationsDidInstall: -> _notificationSourcesDidInstall:,
 * which is what creates the BulletinBoard section behind Settings > Notifications.
 * An app that never went through that flow (sideloaded, or installed while the
 * observer was not listening) has no section, so an authorization decision has
 * nowhere to persist and the prompt repeats forever. Replay that one call. */
static BOOL SGNLegacyEnsureNotificationSource(NSString *bundleIdentifier) {
    if (SGNLegacyRegisteredSourceDescription(bundleIdentifier)) return YES;

    id server = SGNLegacyUserNotificationServer();
    if (![server respondsToSelector:@selector(_notificationSourcesDidInstall:)]) {
        NSLog(@"[SGN] Legacy source install unavailable for %@", bundleIdentifier);
        return NO;
    }
    UNSNotificationSourceDescription *source =
        (UNSNotificationSourceDescription *)SGNNotificationSourceForBundleIdentifier(
            bundleIdentifier);
    if (!source) {
        NSLog(@"[SGN] Legacy source install: no description for %@", bundleIdentifier);
        return NO;
    }

    Class proxyClass = NSClassFromString(@"LSApplicationProxy");
    LSApplicationProxy *proxy = [proxyClass respondsToSelector:
        @selector(applicationProxyForIdentifier:)]
        ? [proxyClass applicationProxyForIdentifier:bundleIdentifier] : nil;
    NSString *lsName = [proxy respondsToSelector:@selector(localizedName)]
        ? [proxy localizedName] : nil;

    if ([lsName length] == 0 || [[source bundleIdentifier] length] == 0) {
        return NO;
    }

    if ([source respondsToSelector:@selector(setDisplayName:)] &&
        [[source displayName] length] == 0) {
        [source setDisplayName:lsName];
    }

    NSLog(@"[SGN] Legacy source install: registering %@ (name=%@)",
          bundleIdentifier, [source displayName]);
    [(UNSUserNotificationServer *)server _notificationSourcesDidInstall:
        [NSArray arrayWithObject:source]];

    BOOL registered = SGNLegacyRegisteredSourceDescription(bundleIdentifier) != nil;
    NSLog(@"[SGN] Legacy source install for %@: %@", bundleIdentifier,
          registered ? @"registered" : @"did not take");
    return registered;
}

/* Registry description preferred; a synthesized one is detached from the store
 * the settings service persists against, so it can prompt but never stick. */
static id SGNLegacySourceDescription(NSString *bundleIdentifier) {
    if (!SGNLegacyEnsureNotificationSource(bundleIdentifier)) return nil;
    return SGNLegacyRegisteredSourceDescription(bundleIdentifier);
}

static NSArray *SGNLegacySafeIdentifiers(id remoteServer) {
    /* iOS 12 keys registrations under _bundleIdentifiersToRegistration; older
     * legacy builds used _bundleIdentifiersToClients. Reading the wrong name
     * yields nil, which silently lists nothing. */
    id clients = GetIvar(remoteServer, "_bundleIdentifiersToRegistration");
    if (!clients) clients = GetIvar(remoteServer, "_bundleIdentifiersToClients");
    if (!clients) clients = GetIvar(remoteServer, "_bundleIdentifiersToDescriptions");
    NSArray *identifiers = [clients isKindOfClass:[NSDictionary class]]
        ? [clients allKeys] : nil;
    return SGNFilteredSortedBundleIdentifiers(identifiers);
}

@interface SGUserNotificationsServerBackend : NSObject <SGNotificationBackend>
@end

@implementation SGUserNotificationsServerBackend

+ (BOOL)isSupported {
    id registrar = SGNLegacyRegistrar();
    id remoteServer = SGNLegacyRemoteNotificationServer();
    return SGNLegacyUserNotificationServer() && registrar && remoteServer &&
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
    if (!SBApp_LookupByIdentifier(bundleIdentifier)) {
        if (completion) completion(SGCERR_NOT_FOUND,
                                   @"application not found");
        return;
    }

    id remoteServer = SGNLegacyRemoteNotificationServer();
    if (![remoteServer respondsToSelector:
        @selector(requestRemoteNotificationTokenWithEnvironment:
                  forBundleIdentifier:)]) {
        if (completion) completion(SGCERR_UNSUPPORTED,
                                   @"legacy native token request unavailable");
        return;
    }

    id source = SGNLegacySourceDescription(bundleIdentifier);
    NSString *environment = [source respondsToSelector:@selector(pushEnvironment)]
        ? [source pushEnvironment] : nil;
    if (!source) {
        if (completion) completion(SGCERR_NOT_FOUND,
                                   @"application notification metadata unavailable");
        return;
    }
    if (![environment length]) {
        if (completion) completion(SGCERR_UNSUPPORTED,
            @"application has no valid aps-environment entitlement");
        return;
    }

    @try {
        /* Fire and forget: the token lands asynchronously on the APS delegate
         * (connection:didReceiveToken:forTopic:identifier:), not through here. */
        [(UNSRemoteNotificationServer *)remoteServer
            requestRemoteNotificationTokenWithEnvironment:environment
                                     forBundleIdentifier:bundleIdentifier];
        if (completion) completion(SGCERR_OK, nil);
    } @catch (NSException *exception) {
        if (completion) completion(SGCERR_INTERNAL,
            [exception reason] ?: @"legacy registration exception");
    }
}

- (SGControlError)beginAuthorizationForBundleIdentifier:
    (NSString *)bundleIdentifier detail:(NSString **)detail {
    if (detail) *detail = nil;
    if (!SG_IsIdentifierStringSafe(bundleIdentifier)) {
        if (detail) *detail = @"bundle id invalid";
        return SGCERR_INVALID_REQUEST;
    }

    /* The connection listener's requestAuthorizationWithOptions:forBundleIdentifier:
     * is the XPC entry point: it resolves the caller through _currentConnection,
     * which is nil for an in-process call, so its entitlement check always fails.
     * Talk to the settings service it delegates to instead. */
    id settingsService =
        GetIvar(SGNLegacyUserNotificationServer(), "_notificationSettingsService");
    if (!settingsService) {
        settingsService = GetIvar(SGNLegacyRegistrar(), "_notificationSettingsService");
    }
    if (![settingsService respondsToSelector:
        @selector(requestAuthorizationWithOptions:
                  forNotificationSourceDescription:completionHandler:)]) {
        if (detail) *detail =
            @"separate authorization is unavailable on this iOS version";
        return SGCERR_UNSUPPORTED;
    }

    id source = SGNLegacySourceDescription(bundleIdentifier);
    if (!source) {
        if (detail) *detail = @"application notification metadata unavailable";
        return SGCERR_NOT_FOUND;
    }

    NSString *bundleCopy = [bundleIdentifier copy];
    @try {
        /* The public entry point hops onto the service's own _queue for us. */
        [(UNSNotificationSettingsService *)settingsService
            requestAuthorizationWithOptions:7
           forNotificationSourceDescription:source
                          completionHandler:^(BOOL granted, NSError *error) {
                NSLog(@"[SGN] Legacy authorization completed for %@: %@%@",
                      bundleCopy, granted ? @"granted" : @"denied",
                      error ? [NSString stringWithFormat:@" (%@)", error] : @"");
                [bundleCopy release];
            }];
        return SGCERR_OK;
    } @catch (NSException *exception) {
        if (detail) {
            *detail = [exception reason]
                ?: @"legacy authorization request exception";
        }
        [bundleCopy release];
        return SGCERR_INTERNAL;
    }
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

    NSString *detail = nil;
    SGControlError authorizationResult =
        [self beginAuthorizationForBundleIdentifier:bundleIdentifier
                                             detail:&detail];
    if (authorizationResult != SGCERR_OK &&
        authorizationResult != SGCERR_UNSUPPORTED) {
        if (completion) completion(authorizationResult, detail);
        return;
    }
    SGN_AsyncFetchAndDeliverToken(bundleIdentifier, nil, nil, 0, completion);
}

@end
