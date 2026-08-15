#import "SGPlatformFactory.h"
#import "system/power/SGSystemPowerCommon.h"
#import <TargetConditionals.h>

#if TARGET_OS_OSX
#import "keychain/SGKeyStoreMac.h"
#import "delivery/SGDeliveryMac.h"
#import "network/SGNetworkInfoMac.h"
#else
#import "keychain/SGKeyStoreIOS.h"
#import "delivery/SGDeliveryIOS.h"
#import "network/SGNetworkInfoIOS.h"
#endif

id<SGKeyStore> SGPlatformCreateKeyStore(void) {
#if TARGET_OS_OSX
    return [[SGKeyStoreMac alloc] init];
#else
    return [[SGKeyStoreIOS alloc] init];
#endif
}

id<SGNotificationDelivery> SGPlatformCreateDelivery(void) {
#if TARGET_OS_OSX
    return [[SGDeliveryMac alloc] init];
#else
    return [[SGDeliveryIOS alloc] init];
#endif
}

id<SGNetworkInfo> SGPlatformCreateNetworkInfo(void) {
#if TARGET_OS_OSX
    return [[SGNetworkInfoMac alloc] init];
#else
    return [[SGNetworkInfoIOS alloc] init];
#endif
}

SGSystemServices *SGPlatformCreateSystemServices(void) {
    id<SGSystemPower> power = [[[SGSystemPowerCommon alloc] init] autorelease];
    return [[SGSystemServices alloc] initWithPower:power];
}
