#import "SGPlatform.h"
#import "SGPlatformFactory.h"

@implementation SGPlatform {
    SGCapabilityTable         *_capabilities;
    id<SGKeyStore>             _keyStore;
    id<SGNotificationDelivery> _delivery;
    id<SGNetworkInfo>          _network;
    SGSystemServices          *_system;
}

+ (instancetype)currentPlatform {
    static SGPlatform *sPlatform = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sPlatform = [[self alloc] init];
    });
    return sPlatform;
}

- (id)init {
    if ((self = [super init])) {
        _capabilities = [[SGCapabilityTable alloc] init];
        _keyStore     = SGPlatformCreateKeyStore();
        _delivery     = SGPlatformCreateDelivery();
        _network      = SGPlatformCreateNetworkInfo();
        _system       = SGPlatformCreateSystemServices();
    }
    return self;
}

- (BOOL)hasCapability:(SGCapability)capability { return [_capabilities hasCapability:capability]; }

- (id<SGKeyStore>)keyStore { return _keyStore; }
- (id<SGNotificationDelivery>)delivery { return _delivery; }
- (id<SGNetworkInfo>)network { return _network; }
- (SGSystemServices *)system { return _system; }

@end
