#ifndef SKYGLOW_SG_CONTROL_COMMAND_ROUTER_H
#define SKYGLOW_SG_CONTROL_COMMAND_ROUTER_H

#import <Foundation/Foundation.h>

@class SGDaemon;
@class SGControlChannel;

@interface SGControlCommandRouter : NSObject
- (instancetype)initWithDaemon:(SGDaemon *)daemon;
- (void)attachToChannel:(SGControlChannel *)channel;
@end

#endif
