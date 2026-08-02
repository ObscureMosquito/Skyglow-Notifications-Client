#import "SGNNativePushBroker.h"
#import "SGNotificationBackend.h"

@interface SGUnsupportedNotificationBackend : NSObject <SGNotificationBackend>
@end

@implementation SGUnsupportedNotificationBackend

+ (BOOL)isSupported { return YES; }

- (NSArray *)registeredBundleIdentifiersWithError:(SGControlError *)error
                                             detail:(NSString **)detail {
    if (error) *error = SGCERR_UNSUPPORTED;
    if (detail) *detail = @"notification backend unavailable";
    return nil;
}

- (void)registerBundleIdentifier:(NSString *)bundleIdentifier
                       completion:(SGNNativePushBrokerCompletion)completion {
    if (completion) completion(SGCERR_UNSUPPORTED,
                               @"native registration backend unavailable");
}

- (SGControlError)beginAuthorizationForBundleIdentifier:
    (NSString *)bundleIdentifier detail:(NSString **)detail {
    if (detail) *detail = @"notification authorization backend unavailable";
    return SGCERR_UNSUPPORTED;
}

- (void)resetBundleIdentifier:(NSString *)bundleIdentifier
                    completion:(SGNNativePushBrokerCompletion)completion {
    if (completion) completion(SGCERR_UNSUPPORTED,
                               @"notification reset backend unavailable");
}

- (void)deliverAPNSPayload:(NSDictionary *)payload
        toBundleIdentifier:(NSString *)bundleIdentifier
                completion:(SGNNativePushBrokerCompletion)completion {
    if (completion) completion(SGCERR_UNSUPPORTED,
                               @"notification delivery backend unavailable");
}

- (void)activateSkyglowForBundleIdentifier:(NSString *)bundleIdentifier
                                completion:(SGNNativePushBrokerCompletion)completion {
    if (completion) completion(SGCERR_UNSUPPORTED,
                               @"Skyglow activation backend unavailable");
}

@end

static id<SGNotificationBackend> SGNotificationBackendCreate(void) {
    NSArray *backendClassNames = @[
        @"SGUserNotificationsCoreBackend",
        @"SGUserNotificationsServerBackend",
        @"SGSpringBoardRemoteNotificationBackend"
    ];
    for (NSString *className in backendClassNames) {
        Class backendClass = NSClassFromString(className);
        if (backendClass && [backendClass conformsToProtocol:
                @protocol(SGNotificationBackend)] &&
            [backendClass respondsToSelector:@selector(isSupported)] &&
            [backendClass isSupported]) {
            NSLog(@"[SGN] Selected notification backend: %@", className);
            return [[backendClass alloc] init];
        }
    }
    NSLog(@"[SGN] No supported notification backend found");
    return [[SGUnsupportedNotificationBackend alloc] init];
}

@implementation SGNNativePushBroker

+ (instancetype)sharedBroker {
    static SGNNativePushBroker *broker = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        broker = [[self alloc] init];
    });
    return broker;
}

- (instancetype)init {
    self = [super init];
    if (self) _backend = SGNotificationBackendCreate();
    return self;
}

- (void)dealloc {
    [_backend release];
    [super dealloc];
}

- (NSArray *)registeredBundleIdentifiersWithError:(SGControlError *)error
                                             detail:(NSString **)detail {
    return [_backend registeredBundleIdentifiersWithError:error detail:detail];
}

- (void)registerBundleIdentifier:(NSString *)bundleIdentifier
                       completion:(SGNNativePushBrokerCompletion)completion {
    [_backend registerBundleIdentifier:bundleIdentifier completion:completion];
}

- (SGControlError)beginAuthorizationForBundleIdentifier:
    (NSString *)bundleIdentifier detail:(NSString **)detail {
    return [_backend beginAuthorizationForBundleIdentifier:bundleIdentifier
                                                     detail:detail];
}

- (void)resetBundleIdentifier:(NSString *)bundleIdentifier
                    completion:(SGNNativePushBrokerCompletion)completion {
    [_backend resetBundleIdentifier:bundleIdentifier completion:completion];
}

- (void)deliverAPNSPayload:(NSDictionary *)payload
        toBundleIdentifier:(NSString *)bundleIdentifier
                completion:(SGNNativePushBrokerCompletion)completion {
    [_backend deliverAPNSPayload:payload
             toBundleIdentifier:bundleIdentifier
                     completion:completion];
}

- (void)activateSkyglowForBundleIdentifier:(NSString *)bundleIdentifier
                                completion:(SGNNativePushBrokerCompletion)completion {
    [_backend activateSkyglowForBundleIdentifier:bundleIdentifier
                                      completion:completion];
}

@end
