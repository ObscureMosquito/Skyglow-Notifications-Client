#import "SGReachabilityMonitor.h"
#import <SystemConfiguration/SystemConfiguration.h>
#include <netinet/in.h>

@implementation SGReachabilityMonitor {
    SCNetworkReachabilityRef _reachabilityRef;
    SGReachabilityChangeHandler _handler;
}

static void SGReachabilityCallback(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags flags, void *info) {
    SGReachabilityMonitor *monitor = (__bridge SGReachabilityMonitor *)info;
    BOOL reachable = (flags & kSCNetworkFlagsReachable) && !(flags & kSCNetworkFlagsConnectionRequired);
    BOOL isWWAN = (flags & kSCNetworkReachabilityFlagsIsWWAN);
    
    if (monitor->_handler) monitor->_handler(reachable, isWWAN);
}

- (instancetype)initWithChangeHandler:(SGReachabilityChangeHandler)handler {
    if ((self = [super init])) {
        _handler = [handler copy];
    }
    return self;
}

- (void)dealloc {
    [self stopMonitoringSystemNetworkChanges];
    [_handler release];
    [super dealloc];
}

- (void)startMonitoringSystemNetworkChanges {
    struct sockaddr_in zeroAddr;
    memset(&zeroAddr, 0, sizeof(zeroAddr));
    zeroAddr.sin_len = sizeof(zeroAddr);
    zeroAddr.sin_family = AF_INET;

    _reachabilityRef = SCNetworkReachabilityCreateWithAddress(NULL, (const struct sockaddr *)&zeroAddr);
    SCNetworkReachabilityContext ctx = {0, (__bridge void *)self, NULL, NULL, NULL};
    SCNetworkReachabilitySetCallback(_reachabilityRef, SGReachabilityCallback, &ctx);
    SCNetworkReachabilitySetDispatchQueue(_reachabilityRef, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0));
}

- (void)stopMonitoringSystemNetworkChanges {
    if (_reachabilityRef) {
        SCNetworkReachabilitySetCallback(_reachabilityRef, NULL, NULL);
        SCNetworkReachabilitySetDispatchQueue(_reachabilityRef, NULL);
        CFRelease(_reachabilityRef);
        _reachabilityRef = NULL;
    }
}

- (BOOL)isReachable {
    SCNetworkReachabilityFlags flags = 0;
    if (_reachabilityRef) SCNetworkReachabilityGetFlags(_reachabilityRef, &flags);
    return (flags & kSCNetworkFlagsReachable) && !(flags & kSCNetworkFlagsConnectionRequired);
}

- (BOOL)isWWAN {
    SCNetworkReachabilityFlags flags = 0;
    if (_reachabilityRef) SCNetworkReachabilityGetFlags(_reachabilityRef, &flags);
    return (flags & kSCNetworkReachabilityFlagsIsWWAN);
}

@end