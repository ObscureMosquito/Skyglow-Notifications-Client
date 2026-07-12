#import <Foundation/Foundation.h>
#import "SGControlChannelProtocol.h"

typedef void (^SGNNativePushBrokerCompletion)(SGControlError error,
                                               NSString *detail);

/* One coherent implementation of SpringBoard's notification operations for
 * an OS family. Capability selection happens once inside the broker. */
@protocol SGNotificationBackend <NSObject>

+ (BOOL)isSupported;
- (NSArray *)registeredBundleIdentifiersWithError:(SGControlError *)error
                                             detail:(NSString **)detail;
- (void)registerBundleIdentifier:(NSString *)bundleIdentifier
                       completion:(SGNNativePushBrokerCompletion)completion;
- (SGControlError)beginAuthorizationForBundleIdentifier:
    (NSString *)bundleIdentifier detail:(NSString **)detail;
- (void)resetBundleIdentifier:(NSString *)bundleIdentifier
                    completion:(SGNNativePushBrokerCompletion)completion;
- (void)deliverAPNSPayload:(NSDictionary *)payload
        toBundleIdentifier:(NSString *)bundleIdentifier
                completion:(SGNNativePushBrokerCompletion)completion;
- (void)activateSkyglowForBundleIdentifier:(NSString *)bundleIdentifier
                                completion:(SGNNativePushBrokerCompletion)completion;

@end

/*
 * Stable SpringBoard facade across classic, legacy UserNotifications, and
 * current UserNotificationsCore implementations. Private objects stay behind
 * the selected backend; callers only see bundle IDs and SGControlError.
 */
@interface SGNNativePushBroker : NSObject {
@private
    id _backend;
}

+ (instancetype)sharedBroker;

- (NSArray *)registeredBundleIdentifiersWithError:(SGControlError *)error
                                             detail:(NSString **)detail;
- (void)registerBundleIdentifier:(NSString *)bundleIdentifier
                       completion:(SGNNativePushBrokerCompletion)completion;
- (SGControlError)beginAuthorizationForBundleIdentifier:
    (NSString *)bundleIdentifier detail:(NSString **)detail;
- (void)resetBundleIdentifier:(NSString *)bundleIdentifier
                    completion:(SGNNativePushBrokerCompletion)completion;
- (void)deliverAPNSPayload:(NSDictionary *)payload
        toBundleIdentifier:(NSString *)bundleIdentifier
                completion:(SGNNativePushBrokerCompletion)completion;
- (void)activateSkyglowForBundleIdentifier:(NSString *)bundleIdentifier
                                completion:(SGNNativePushBrokerCompletion)completion;

@end
