#ifndef SKYGLOW_SG_NOTIFICATION_SENDER_H
#define SKYGLOW_SG_NOTIFICATION_SENDER_H

#import <Foundation/Foundation.h>
#import <mach/mach.h>

@class SGControlChannel;

/*
 * The daemon's single outlet for surfacing a decoded notification. Hides the
 * receiver, usernoted (macOS) or the SpringBoard (iOS)
 */
@interface SGNotificationSender : NSObject

// channel is the SpringBoard control client, used on iOS; ignored on macOS.
- (instancetype)initWithSpringBoardChannel:(SGControlChannel *)channel;

// payload is a canonical aps dict (or a {"aps":{...}} wrapper). KERN_SUCCESS
// once handed off; any failure leaves it for the daemon's retry path.
- (kern_return_t)sendNotificationForBundleID:(NSString *)bundleID
                                     payload:(NSDictionary *)payload;

@end

#endif
