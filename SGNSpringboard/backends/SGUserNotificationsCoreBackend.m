#import "SGNotificationBackend.h"

#import "SGNAppIntent.h"
#import "SGNDaemonBridge.h"
#import "SGNPrivateAPI.h"

static id SGNModernUserNotificationServer(void) {
    Class serverClass = NSClassFromString(@"UNSUserNotificationServer");
    return [serverClass respondsToSelector:@selector(sharedInstance)]
        ? [serverClass sharedInstance] : nil;
}

static NSArray *SGNCoreRegisteredBundleIdentifiers(id repository) {
    NSArray *identifiers = [repository respondsToSelector:
        @selector(allBundleIdentifiers)]
        ? [repository allBundleIdentifiers] : nil;
    return SGNFilteredSortedBundleIdentifiers(identifiers);
}

@interface SGUserNotificationsCoreBackend : NSObject <SGNotificationBackend>
@end

@implementation SGUserNotificationsCoreBackend

+ (BOOL)isSupported {
    id server = SGNModernUserNotificationServer();
    id remoteService = GetIvar(server, "_remoteNotificationService");
    return server && remoteService &&
        GetIvar(server, "_pushRegistrationRepository") &&
        GetIvar(remoteService, "_queue") &&
        [remoteService respondsToSelector:
            @selector(_queue_canDeliverMessageToBundle:)] &&
        [remoteService respondsToSelector:
            @selector(_queue_messageIsValidForDelivery:)] &&
        [remoteService respondsToSelector:
            @selector(_queue_didReceiveIncomingMessage:)];
}

- (NSArray *)registeredBundleIdentifiersWithError:(SGControlError *)error
                                             detail:(NSString **)detail {
    if (error) *error = SGCERR_OK;
    if (detail) *detail = nil;

    id server = SGNModernUserNotificationServer();
    id repository = GetIvar(server, "_pushRegistrationRepository");
    if (!server || !repository) {
        if (error) *error = SGCERR_UNSUPPORTED;
        if (detail) *detail = @"native push repository unavailable";
        return nil;
    }

    @try {
        return SGNCoreRegisteredBundleIdentifiers(repository);
    } @catch (NSException *exception) {
        NSLog(@"[SGN] Native push enumeration failed: %@", exception);
        if (error) *error = SGCERR_INTERNAL;
        if (detail) *detail = [exception reason] ?: @"native push enumeration failed";
        return nil;
    }
}

- (void)deliverAPNSPayload:(NSDictionary *)payload
        toBundleIdentifier:(NSString *)bundleIdentifier
                completion:(SGNNativePushBrokerCompletion)completion {
    if (!SG_IsIdentifierStringSafe(bundleIdentifier) ||
        ![payload isKindOfClass:[NSDictionary class]]) {
        if (completion) completion(SGCERR_INVALID_REQUEST,
                                   @"native delivery input invalid");
        return;
    }

    Class messageClass = NSClassFromString(@"APSIncomingMessage");
    APSIncomingMessage *message = [[messageClass alloc]
        initWithTopic:bundleIdentifier userInfo:payload];
    if (!message) {
        if (completion) completion(SGCERR_UNSUPPORTED,
                                   @"APS incoming-message class unavailable");
        return;
    }
    if ([message respondsToSelector:@selector(setTimestamp:)]) {
        [message setTimestamp:[NSDate date]];
    }
    NSString *correlationIdentifier =
        [message respondsToSelector:@selector(correlationIdentifier)]
            ? [message correlationIdentifier] : nil;
    if (![correlationIdentifier length] &&
        [message respondsToSelector:@selector(setCorrelationIdentifier:)]) {
        correlationIdentifier = [[NSUUID UUID] UUIDString];
        [message setCorrelationIdentifier:correlationIdentifier];
    }

    if ([message respondsToSelector:@selector(setPriority:)]) {
        [message setPriority:10];
    }
    if ([message respondsToSelector:@selector(setPushType:)]) {
        [message setPushType:0]; /* alert */
    }

    id server = SGNModernUserNotificationServer();
    id remoteService = [GetIvar(server, "_remoteNotificationService") retain];
    dispatch_queue_t remoteQueue =
        (dispatch_queue_t)GetIvar(remoteService, "_queue");
    BOOL hasValidatedQueuePath = remoteService && remoteQueue &&
        [remoteService respondsToSelector:
            @selector(_queue_canDeliverMessageToBundle:)] &&
        [remoteService respondsToSelector:
            @selector(_queue_messageIsValidForDelivery:)] &&
        [remoteService respondsToSelector:
            @selector(_queue_didReceiveIncomingMessage:)];
    if (!hasValidatedQueuePath) {
        if (completion) completion(SGCERR_UNSUPPORTED,
                                   @"UserNotificationsCore service unavailable");
        [message release];
        [remoteService release];
        return;
    }

    NSString *bundleCopy = [bundleIdentifier copy];
    SGNNativePushBrokerCompletion completionCopy = [completion copy];
    dispatch_async(remoteQueue, ^{
        SGControlError result = SGCERR_OK;
        NSString *detail = nil;
        @try {
            NSString *messageBundle =
                [message respondsToSelector:@selector(unc_bundleIdentifier)]
                    ? [message unc_bundleIdentifier] : bundleCopy;
            BOOL messageValid = [remoteService
                _queue_messageIsValidForDelivery:message];
            NSString *requestIdentifier =
                [message respondsToSelector:@selector(correlationIdentifier)]
                    ? [message correlationIdentifier] : nil;
            NSDictionary *messagePayload =
                [message respondsToSelector:@selector(userInfo)]
                    ? [message userInfo] : nil;
            Class requestClass = NSClassFromString(@"UNNotificationRequest");
            UNNotificationRequest *request =
                [requestClass respondsToSelector:
                    @selector(requestWithIdentifier:pushPayload:
                              bundleIdentifier:)]
                    ? [requestClass requestWithIdentifier:requestIdentifier
                                              pushPayload:messagePayload
                                         bundleIdentifier:messageBundle]
                    : nil;
            id content = [request respondsToSelector:@selector(content)]
                ? [request content] : nil;
            BOOL willNotify = [content respondsToSelector:
                @selector(unc_willNotifyUser)] && [content unc_willNotifyUser];
            BOOL willAlert = [content respondsToSelector:
                @selector(unc_willAlertUser)] && [content unc_willAlertUser];
            id aps = [messagePayload objectForKey:@"aps"];
            id alert = [aps isKindOfClass:[NSDictionary class]]
                ? [aps objectForKey:@"alert"] : nil;
            BOOL expectsAlert = alert != nil && alert != [NSNull null];
            BOOL visibleNotificationsEnabled =
                ![remoteService respondsToSelector:@selector(
                    _queue_isVisibleUserNotificationEnabledForApplication:)] ||
                [remoteService
                    _queue_isVisibleUserNotificationEnabledForApplication:
                        messageBundle];
            BOOL nativeDeliveryAllowed = [remoteService
                _queue_canDeliverMessageToBundle:messageBundle];

            NSLog(@"[SGN] Push preflight bundle=%@ request=%@ priority=%ld "
                  @"pushType=%ld willNotify=%d willAlert=%d visibleEnabled=%d "
                  @"nativeGate=%d",
                  bundleCopy, request ? @"valid" : @"invalid",
                  (long)([message respondsToSelector:@selector(priority)]
                      ? [message priority] : -1),
                  (long)([message respondsToSelector:@selector(pushType)]
                      ? [message pushType] : -1),
                  willNotify, willAlert, visibleNotificationsEnabled,
                  nativeDeliveryAllowed);

            if (![messageBundle isEqualToString:bundleCopy]) {
                result = SGCERR_INTERNAL;
                detail = @"APS message resolved to a different bundle id";
            } else if (!messageValid) {
                result = SGCERR_INVALID_REQUEST;
                detail = @"native push service rejected the APS push type";
            } else if (!request) {
                result = SGCERR_INVALID_REQUEST;
                detail = @"Apple rejected the remote notification payload";
            } else if (expectsAlert && !willAlert) {
                result = SGCERR_INVALID_REQUEST;
                detail = @"Apple parsed the payload as non-alerting";
            } else if (!willNotify) {
                result = SGCERR_INVALID_REQUEST;
                detail = @"Apple parsed the payload as non-notifying";
            } else if (expectsAlert && !visibleNotificationsEnabled) {
                result = SGCERR_INTERNAL;
                detail = @"visible notifications are disabled for the application";
            } else if (nativeDeliveryAllowed) {
                /* Native APNs registrations keep Apple's complete receive
                 * pipeline, including background delivery behavior. */
                [remoteService _queue_didReceiveIncomingMessage:message];
            } else {
                /* Skyglow deliberately does not require aps-environment or an
                 * Apple token. Authorization remains Apple's source of truth;
                 * only the APNs-registration gate is bypassed. */
                id repository = GetIvar(remoteService,
                                        "_notificationRepository");
                SEL saveSelector = @selector(saveNotificationRequest:
                    shouldRepost:withMessage:forBundleIdentifier:);
                if (!SBApp_LookupByIdentifier(messageBundle)) {
                    result = SGCERR_NOT_FOUND;
                    detail = @"application is no longer installed";
                } else if (!visibleNotificationsEnabled) {
                    result = SGCERR_INTERNAL;
                    detail = @"notifications are not authorized for the application";
                } else if (![repository respondsToSelector:saveSelector]) {
                    result = SGCERR_UNSUPPORTED;
                    detail = @"UserNotificationsCore repository unavailable";
                } else {
                    [repository saveNotificationRequest:request
                                           shouldRepost:YES
                                            withMessage:message
                                    forBundleIdentifier:messageBundle];
                    NSLog(@"[SGN] Delivered through UserNotificationsCore repository: %@",
                          messageBundle);
                }
            }
        } @catch (NSException *exception) {
            NSLog(@"[SGN] UserNotificationsCore delivery failed for %@: %@",
                  bundleCopy, exception);
            result = SGCERR_INTERNAL;
            detail = [exception reason] ?: @"UserNotificationsCore delivery exception";
        }

        if (completionCopy) completionCopy(result, detail);
        [bundleCopy release];
        [completionCopy release];
        [message release];
        [remoteService release];
    });
}

- (void)registerBundleIdentifier:(NSString *)bundleIdentifier
                       completion:(SGNNativePushBrokerCompletion)completion {
    if (!SG_IsIdentifierStringSafe(bundleIdentifier)) {
        if (completion) completion(SGCERR_INVALID_REQUEST, @"bundle id invalid");
        return;
    }

    id server = SGNModernUserNotificationServer();
    id repository = [GetIvar(server, "_pushRegistrationRepository") retain];
    id remoteService = [GetIvar(server, "_remoteNotificationService") retain];
    dispatch_queue_t remoteQueue = (dispatch_queue_t)GetIvar(remoteService, "_queue");
    id source = SGNNotificationSourceForBundleIdentifier(bundleIdentifier);
    NSString *environment = [source respondsToSelector:@selector(pushEnvironment)]
        ? [source pushEnvironment] : nil;

    if (!server || !repository || !remoteService || !remoteQueue) {
        [repository release];
        [remoteService release];
        if (completion) completion(SGCERR_UNSUPPORTED,
                                   @"native registration service unavailable");
        return;
    }
    if (!source) {
        [repository release];
        [remoteService release];
        if (completion) completion(SGCERR_NOT_FOUND,
                                   @"application notification metadata unavailable");
        return;
    }
    if (![environment length]) {
        [repository release];
        [remoteService release];
        if (completion) completion(SGCERR_UNSUPPORTED,
                                   @"application has no valid aps-environment entitlement");
        return;
    }
    if (![remoteService respondsToSelector:
        @selector(requestRemoteNotificationTokenWithEnvironment:forBundleIdentifier:)]) {
        [repository release];
        [remoteService release];
        if (completion) completion(SGCERR_UNSUPPORTED,
                                   @"native token request method unavailable");
        return;
    }

    NSString *bundleCopy = [bundleIdentifier copy];
    SGNNativePushBrokerCompletion completionCopy = [completion copy];
    @try {
        [remoteService requestRemoteNotificationTokenWithEnvironment:environment
                                                  forBundleIdentifier:bundleCopy];
        /* The public method enqueues the registration mutation on _queue.
         * Our following block is therefore a FIFO persistence fence. */
        dispatch_async(remoteQueue, ^{
            BOOL registered = [SGNCoreRegisteredBundleIdentifiers(repository)
                containsObject:bundleCopy];
            if (completionCopy) {
                completionCopy(registered ? SGCERR_OK : SGCERR_INTERNAL,
                    registered ? nil : @"native registration was not persisted");
            }
            [bundleCopy release];
            [completionCopy release];
            [repository release];
            [remoteService release];
        });
    } @catch (NSException *exception) {
        NSLog(@"[SGN] Native registration failed for %@: %@",
              bundleCopy, exception);
        if (completionCopy) {
            completionCopy(SGCERR_INTERNAL,
                [exception reason] ?: @"native registration raised an exception");
        }
        [bundleCopy release];
        [completionCopy release];
        [repository release];
        [remoteService release];
    }
}

- (SGControlError)beginAuthorizationForBundleIdentifier:
    (NSString *)bundleIdentifier detail:(NSString **)detail {
    if (detail) *detail = nil;
    if (!SG_IsIdentifierStringSafe(bundleIdentifier)) {
        if (detail) *detail = @"bundle id invalid";
        return SGCERR_INVALID_REQUEST;
    }

    id server = SGNModernUserNotificationServer();
    id authorizationService =
        GetIvar(server, "_notificationAuthorizationService");
    id source = SGNNotificationSourceForBundleIdentifier(bundleIdentifier);
    SEL requestSelector = @selector(requestAuthorizationWithOptions:
        forNotificationSourceDescription:completionHandler:);
    if (!server || !authorizationService ||
        ![authorizationService respondsToSelector:requestSelector]) {
        if (detail) *detail = @"native authorization service unavailable";
        return SGCERR_UNSUPPORTED;
    }
    if (!source) {
        if (detail) *detail =
            @"application notification metadata unavailable";
        return SGCERR_NOT_FOUND;
    }

    NSString *bundleCopy = [bundleIdentifier copy];
    @try {
        /* UNAuthorizationOptionBadge | Sound | Alert.  The service owns the
         * normal Apple prompt and persists the user's decision. */
        [authorizationService
            requestAuthorizationWithOptions:7
            forNotificationSourceDescription:source
            completionHandler:^(BOOL granted, NSError *error) {
                if (error) {
                    NSLog(@"[SGN] Native authorization failed for %@: %@",
                          bundleCopy, error);
                } else {
                    NSLog(@"[SGN] Native authorization completed for %@: %@",
                          bundleCopy, granted ? @"granted" : @"denied");
                }
                [bundleCopy release];
            }];
        return SGCERR_OK;
    } @catch (NSException *exception) {
        NSLog(@"[SGN] Native authorization request failed for %@: %@",
              bundleCopy, exception);
        if (detail) {
            *detail = [exception reason]
                ?: @"native authorization request exception";
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

    id server = SGNModernUserNotificationServer();
    id repository = [GetIvar(server, "_pushRegistrationRepository") retain];
    id remoteService = [GetIvar(server, "_remoteNotificationService") retain];
    id authorizationService =
        [GetIvar(server, "_notificationAuthorizationService") retain];
    id settingsGateway = [GetIvar(server, "_settingsGateway") retain];
    dispatch_queue_t remoteQueue = (dispatch_queue_t)GetIvar(remoteService, "_queue");
    dispatch_queue_t settingsQueue = (dispatch_queue_t)GetIvar(settingsGateway, "_queue");
    id source = [SGNNotificationSourceForBundleIdentifier(bundleIdentifier) retain];

    BOOL canInvalidate = [remoteService respondsToSelector:
        @selector(invalidateTokenForRemoteNotificationsForBundleIdentifier:)];
    BOOL canRemoveAuthorization = [authorizationService respondsToSelector:
        @selector(requestRemoveAuthorizationForNotificationSourceDescription:completionHandler:)];
    BOOL canRemoveSettings = settingsQueue &&
        [settingsGateway respondsToSelector:@selector(setSectionInfo:forSectionID:)] &&
        [settingsGateway respondsToSelector:@selector(_queue_sectionInfoForSectionID:)];
    if (!server || !repository || !remoteQueue || !canInvalidate ||
        !source || !canRemoveAuthorization || !canRemoveSettings) {
        [repository release];
        [remoteService release];
        [authorizationService release];
        [settingsGateway release];
        [source release];
        if (completion) completion(source ? SGCERR_UNSUPPORTED : SGCERR_NOT_FOUND,
            source ? @"native reset service unavailable"
                   : @"application notification metadata unavailable");
        return;
    }

    NSString *bundleCopy = [bundleIdentifier copy];
    SGNNativePushBrokerCompletion completionCopy = [completion copy];
    dispatch_group_t group = dispatch_group_create();
    __block BOOL registrationRemoved = NO;
    __block BOOL settingsRemoved = NO;
    __block NSError *authorizationError = nil;

    dispatch_group_enter(group);
    @try {
        [remoteService
            invalidateTokenForRemoteNotificationsForBundleIdentifier:bundleCopy];
        dispatch_async(remoteQueue, ^{
            registrationRemoved = ![SGNCoreRegisteredBundleIdentifiers(repository)
                containsObject:bundleCopy];
            dispatch_group_leave(group);
        });
    } @catch (NSException *exception) {
        NSLog(@"[SGN] Native token invalidation failed for %@: %@",
              bundleCopy, exception);
        dispatch_group_leave(group);
    }

    /* Authorization removal tears down the data provider but does not erase
     * BulletinBoard's persisted permission decision. nil section info is the
     * settings-gateway removal operation; the following queue block is its
     * FIFO persistence fence and verifies the raw section is gone. */
    dispatch_group_enter(group);
    @try {
        [settingsGateway setSectionInfo:nil forSectionID:bundleCopy];
        dispatch_async(settingsQueue, ^{
            settingsRemoved =
                [settingsGateway _queue_sectionInfoForSectionID:bundleCopy] == nil;
            dispatch_group_leave(group);
        });
    } @catch (NSException *exception) {
        NSLog(@"[SGN] Native settings removal failed for %@: %@",
              bundleCopy, exception);
        dispatch_group_leave(group);
    }

    dispatch_group_enter(group);
    @try {
        [authorizationService
            requestRemoveAuthorizationForNotificationSourceDescription:source
            completionHandler:^(BOOL removed, NSError *error) {
                (void)removed; /* Already absent is also the desired state. */
                authorizationError = [error retain];
                dispatch_group_leave(group);
            }];
    } @catch (NSException *exception) {
        authorizationError = [[NSError alloc]
            initWithDomain:@"com.skyglow.sgn.native-push"
                     code:1
                 userInfo:@{NSLocalizedDescriptionKey:
                     [exception reason] ?: @"authorization reset exception"}];
        dispatch_group_leave(group);
    }

    dispatch_group_notify(group,
        dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        SGControlError result = SGCERR_OK;
        NSString *detail = nil;
        if (!registrationRemoved) {
            result = SGCERR_INTERNAL;
            detail = @"native registration was not removed";
        } else if (!settingsRemoved) {
            result = SGCERR_INTERNAL;
            detail = @"notification permission settings were not removed";
        } else if (authorizationError) {
            result = SGCERR_INTERNAL;
            detail = [authorizationError localizedDescription]
                ?: @"authorization reset failed";
        }
        if (completionCopy) completionCopy(result, detail);

        [authorizationError release];
        [bundleCopy release];
        [completionCopy release];
        [repository release];
        [remoteService release];
        [authorizationService release];
        [settingsGateway release];
        [source release];
        dispatch_release(group);
    });
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
    if (authorizationResult != SGCERR_OK) {
        if (completion) completion(authorizationResult, detail);
        return;
    }

    /* Skyglow provides the token; this intentionally does not create an Apple
     * push registration and therefore needs no aps-environment entitlement. */
    SGN_AsyncFetchAndDeliverToken(bundleIdentifier, nil, nil, 0, completion);
}

@end
