#import "NetworkMonitor.h"
#include <netinet/in.h>

@implementation NetworkMonitor {
    SCNetworkReachabilityRef _reachabilityRef;
    NetworkReachabilityChangeBlock _callback;
}

static void ReachabilityCallback(SCNetworkReachabilityRef target,
                                 SCNetworkReachabilityFlags flags,
                                 void *info) {
    NetworkMonitor *monitor = (__bridge NetworkMonitor *)info;
    
    BOOL reachable    = (flags & kSCNetworkFlagsReachable) != 0;
    BOOL needsConn    = (flags & kSCNetworkFlagsConnectionRequired) != 0;
    BOOL isWWAN       = (flags & kSCNetworkReachabilityFlagsIsWWAN) != 0;
    BOOL reachableNow = reachable && !needsConn;

    if (monitor->_callback) {
        monitor->_callback(reachableNow, isWWAN);
    }
}

- (instancetype)initWithCallback:(NetworkReachabilityChangeBlock)callback {
    if ((self = [super init])) {
        _callback = [callback copy];
    }
    return self;
}

- (void)dealloc {
    [self stopMonitoring];
    [_callback release];
    [super dealloc];
}

- (void)startMonitoring {
    struct sockaddr_in zeroAddress;
    memset(&zeroAddress, 0, sizeof(zeroAddress));
    zeroAddress.sin_len    = sizeof(zeroAddress);
    zeroAddress.sin_family = AF_INET;

    _reachabilityRef = SCNetworkReachabilityCreateWithAddress(NULL, (const struct sockaddr *)&zeroAddress);
    if (!_reachabilityRef) {
        NSLog(@"[NetworkMonitor] Failed to create reachability ref");
        return;
    }

    SCNetworkReachabilityContext ctx = {0, (__bridge void *)(self), NULL, NULL, NULL};
    if (!SCNetworkReachabilitySetCallback(_reachabilityRef, ReachabilityCallback, &ctx)) {
        NSLog(@"[NetworkMonitor] Could not set reachability callback");
        return;
    }

    dispatch_queue_t bgQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    if (!SCNetworkReachabilitySetDispatchQueue(_reachabilityRef, bgQueue)) {
        NSLog(@"[NetworkMonitor] Could not set reachability dispatch queue");
    }

    NSLog(@"[NetworkMonitor] Started listening for network changes");
}

- (void)stopMonitoring {
    if (_reachabilityRef) {
        SCNetworkReachabilitySetCallback(_reachabilityRef, NULL, NULL);
        SCNetworkReachabilitySetDispatchQueue(_reachabilityRef, NULL);
        CFRelease(_reachabilityRef);
        _reachabilityRef = NULL;
    }
}

- (BOOL)isReachable {
    SCNetworkReachabilityFlags flags = 0;
    if (_reachabilityRef) {
        SCNetworkReachabilityGetFlags(_reachabilityRef, &flags);
    }
    BOOL reachable = (flags & kSCNetworkFlagsReachable) != 0;
    BOOL needsConn = (flags & kSCNetworkFlagsConnectionRequired) != 0;
    return reachable && !needsConn;
}

- (BOOL)isWWAN {
    SCNetworkReachabilityFlags flags = 0;
    if (_reachabilityRef) {
        SCNetworkReachabilityGetFlags(_reachabilityRef, &flags);
    }
    return (flags & kSCNetworkReachabilityFlagsIsWWAN) != 0;
}

@end