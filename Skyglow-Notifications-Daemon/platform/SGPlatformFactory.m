#import "SGPlatform.h"
#import <TargetConditionals.h>

#if TARGET_OS_OSX
#import "SGMacPlatform.h"
#else
#import "SGIOSPlatform.h"
#endif

id<SGPlatform> SGPlatformCreate(void (^deliveryReadyHandler)(void)) {
#if TARGET_OS_OSX
    return [[SGMacPlatform alloc]
        initWithDeliveryReadyHandler:deliveryReadyHandler];
#else
    return [[SGIOSPlatform alloc]
        initWithDeliveryReadyHandler:deliveryReadyHandler];
#endif
}
