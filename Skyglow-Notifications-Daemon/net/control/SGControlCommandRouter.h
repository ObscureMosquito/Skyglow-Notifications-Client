#ifndef SKYGLOW_SG_CONTROL_COMMAND_ROUTER_H
#define SKYGLOW_SG_CONTROL_COMMAND_ROUTER_H

#import <Foundation/Foundation.h>

@class SGDaemon;
@class SGPlatform;
@class SGControlChannel;

/* Owns the daemon's control-channel command handlers. main() builds it with its
 * collaborators and attaches it to the channel — main() itself handles no IPC. */
@interface SGControlCommandRouter : NSObject
- (instancetype)initWithDaemon:(SGDaemon *)daemon platform:(SGPlatform *)platform;
- (void)attachToChannel:(SGControlChannel *)channel;
@end

#endif
