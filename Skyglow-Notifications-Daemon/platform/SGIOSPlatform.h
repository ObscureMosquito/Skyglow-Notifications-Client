#ifndef SKYGLOW_SG_IOS_PLATFORM_H
#define SKYGLOW_SG_IOS_PLATFORM_H

#import "SGPlatform.h"

@interface SGIOSPlatform : NSObject <SGNativePushPlatform>
- (instancetype)initWithDeliveryReadyHandler:(void (^)(void))handler;
@end

#endif
