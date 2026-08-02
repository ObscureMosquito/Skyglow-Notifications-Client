#pragma once

#import "SGNNativePushBroker.h"

/* Private implementation contract.  SpringBoard-facing callers only depend
 * on SGNNativePushBroker; capability selection and private API objects remain
 * inside the backends directory. */
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

/* Shared private-API adaptation used by multiple backend generations. */
id SGNNotificationSourceForBundleIdentifier(NSString *bundleIdentifier);
NSArray *SGNFilteredSortedBundleIdentifiers(NSArray *identifiers);
