#ifndef SKYGLOW_SG_CONTROL_COMMAND_ROUTER_H
#define SKYGLOW_SG_CONTROL_COMMAND_ROUTER_H

#import <Foundation/Foundation.h>

@class SGDaemon;
@protocol SGPlatform;
@class SGControlChannel;

@interface SGControlCommandRouter : NSObject
- (instancetype)initWithDaemon:(SGDaemon *)daemon
                       platform:(id<SGPlatform>)platform;
- (void)attachToChannel:(SGControlChannel *)channel;
@end

#endif
