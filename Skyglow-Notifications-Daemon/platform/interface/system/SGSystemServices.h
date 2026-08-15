#ifndef SKYGLOW_SG_SYSTEM_SERVICES_H
#define SKYGLOW_SG_SYSTEM_SERVICES_H

#import "power/SGSystemPower.h"

/** holds the kernel/hardware sub-nodes, implements nothing itself. */
@interface SGSystemServices : NSObject

- (id)initWithPower:(id<SGSystemPower>)power;

@property (nonatomic, readonly) id<SGSystemPower> power;

@end

#endif
