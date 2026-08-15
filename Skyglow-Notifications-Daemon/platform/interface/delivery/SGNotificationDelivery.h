#ifndef SKYGLOW_SG_NOTIFICATION_DELIVERY_H
#define SKYGLOW_SG_NOTIFICATION_DELIVERY_H

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import "SGControlChannelProtocol.h"

@protocol SGNotificationDelivery <NSObject>
- (void)setDeliveryReadyHandler:(void (^)(void))handler;
- (BOOL)start;
- (void)stop;
- (SGControlError)sendNotificationForBundleID:(NSString *)bundleID
                                      payload:(NSDictionary *)payload;
- (void)resetAppRegistrationForBundleID:(NSString *)bundleID
                             completion:(void (^)(SGControlError err,
                                                   NSString *detail))completion;
@end

@protocol SGNativePushDelivery <SGNotificationDelivery>
- (void)listNativePushAppsWithCompletion:(void (^)(SGControlError err, NSData *listPayload))completion;
- (void)registerNativePushAppForBundleID:(NSString *)bundleID
                              completion:(void (^)(SGControlError err, NSString *detail))completion;
- (void)requestNativeNotificationAuthorizationForBundleID:(NSString *)bundleID
    completion:(void (^)(SGControlError err, NSString *detail))completion;
- (void)registerInputAppForBundleID:(NSString *)bundleID
                         completion:(void (^)(SGControlError err, NSString *detail))completion;
@end

#endif
