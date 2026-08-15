#import "system/SGSystemServices.h"

@implementation SGSystemServices {
    id<SGSystemPower> _power;
}

- (id)initWithPower:(id<SGSystemPower>)power {
    if ((self = [super init])) {
        _power = [power retain];
    }
    return self;
}

- (void)dealloc {
    [_power release];
    [super dealloc];
}

- (id<SGSystemPower>)power { return _power; }

@end
