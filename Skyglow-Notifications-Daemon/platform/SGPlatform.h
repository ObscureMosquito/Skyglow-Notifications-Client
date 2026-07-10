#ifndef SKYGLOW_SG_PLATFORM_H
#define SKYGLOW_SG_PLATFORM_H

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import "SGControlChannelProtocol.h"

@class SGControlChannel;

/*
 * The daemon's single handle to the platform's notification / registration
 * layer.
 */
@interface SGPlatform : NSObject

- (instancetype)initWithControlChannel:(SGControlChannel *)channel;
- (kern_return_t)sendNotificationForBundleID:(NSString *)bundleID
                                     payload:(NSDictionary *)payload;
- (void)resetAppRegistrationForBundleID:(NSString *)bundleID
                             completion:(void (^)(SGControlError err))completion;
- (void)listNativePushAppsWithCompletion:(void (^)(SGControlError err, NSData *listPayload))completion;
- (void)registerInputAppPayload:(NSData *)bundleIdPayload
                     completion:(void (^)(SGControlError err, NSString *detail))completion;

@end

#endif
