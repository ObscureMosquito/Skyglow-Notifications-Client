#ifndef SKYGLOW_SG_PLATFORM_H
#define SKYGLOW_SG_PLATFORM_H

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import "SGControlChannelProtocol.h"

@protocol SGPlatform <NSObject>

- (BOOL)start;
- (void)stop;
- (kern_return_t)sendNotificationForBundleID:(NSString *)bundleID
                                     payload:(NSDictionary *)payload;
- (void)resetAppRegistrationForBundleID:(NSString *)bundleID
                             completion:(void (^)(SGControlError err,
                                                   NSString *detail))completion;
- (void)listNativePushAppsWithCompletion:(void (^)(SGControlError err, NSData *listPayload))completion;
- (void)registerNativePushAppForBundleID:(NSString *)bundleID
                              completion:(void (^)(SGControlError err,
                                                   NSString *detail))completion;
- (void)requestNativeNotificationAuthorizationForBundleID:(NSString *)bundleID
    completion:(void (^)(SGControlError err, NSString *detail))completion;
- (void)registerInputAppForBundleID:(NSString *)bundleID
                         completion:(void (^)(SGControlError err,
                                               NSString *detail))completion;

@end

FOUNDATION_EXPORT id<SGPlatform> SGPlatformCreate(
    void (^deliveryReadyHandler)(void));

#endif
