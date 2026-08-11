#pragma once

#import "SGNNativePushBroker.h"

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

id SGNNotificationSourceForBundleIdentifier(NSString *bundleIdentifier);
NSArray *SGNFilteredSortedBundleIdentifiers(NSArray *identifiers);
