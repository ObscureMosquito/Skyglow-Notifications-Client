#ifndef SKYGLOW_SG_MAC_PLATFORM_H
#define SKYGLOW_SG_MAC_PLATFORM_H

#import "SGPlatform.h"

@interface SGMacPlatform : NSObject <SGPlatform>
- (instancetype)initWithDeliveryReadyHandler:(void (^)(void))handler;
@end

#endif
