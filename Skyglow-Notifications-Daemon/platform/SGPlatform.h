#ifndef SKYGLOW_SG_PLATFORM_H
#define SKYGLOW_SG_PLATFORM_H

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import "SGControlChannelProtocol.h"

/*
 * The daemon's single handle to the platform's notification / registration
 * layer. Each platform backend owns the transport it needs to reach the local
 * notification system; callers do not construct platform-specific channels.
 */
@interface SGPlatform : NSObject

- (instancetype)initWithDeliveryReadyHandler:(void (^)(void))handler;
- (BOOL)start;
- (void)stop;
- (kern_return_t)sendNotificationForBundleID:(NSString *)bundleID
                                     payload:(NSDictionary *)payload;
- (void)resetAppRegistrationForBundleID:(NSString *)bundleID
                             completion:(void (^)(SGControlError err))completion;
- (void)listNativePushAppsWithCompletion:(void (^)(SGControlError err, NSData *listPayload))completion;
- (void)registerInputAppPayload:(NSData *)bundleIdPayload
                     completion:(void (^)(SGControlError err, NSString *detail))completion;

@end

#endif
