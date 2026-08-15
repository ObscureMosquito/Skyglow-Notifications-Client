#import "SGNetworkInfoIOS.h"
#import <SystemConfiguration/SystemConfiguration.h>

@implementation SGNetworkInfoIOS

- (BOOL)flagsIndicateCellular:(uint32_t)flags {
    return (flags & kSCNetworkReachabilityFlagsIsWWAN) != 0;
}

@end
