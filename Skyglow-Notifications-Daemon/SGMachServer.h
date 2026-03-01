#ifndef SKYGLOW_SG_MACH_SERVER_H
#define SKYGLOW_SG_MACH_SERVER_H

#import <Foundation/Foundation.h>
#import <mach/mach.h>

@interface SGMachServer : NSObject

/**
 * Initializes and starts the Mach bootstrap services for Token and Push requests.
 * Runs the message receive loop on a background thread.
 */
- (void)startMachBootstrapServices;

@end

/**
 * Global helper to route a received push notification to the appropriate app via Mach.
 */
kern_return_t SGMach_SendPushToAppTopic(NSString *topic, NSDictionary *payload);

#endif