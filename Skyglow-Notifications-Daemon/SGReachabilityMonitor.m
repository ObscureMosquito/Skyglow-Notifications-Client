#import "SGReachabilityMonitor.h"
#import <SystemConfiguration/SystemConfiguration.h>
#include <netinet/in.h>

@implementation SGReachabilityMonitor {
    SCNetworkReachabilityRef _reachabilityRef;
    SGReachabilityChangeHandler _handler;
}

static const void *SGReachabilityRetain(const void *info) {
    return [(SGReachabilityMonitor *)info retain];
}
static void SGReachabilityRelease(const void *info) {
    [(SGReachabilityMonitor *)info release];
}

static void SGReachabilityCallback(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags flags, void *info) {
    SGReachabilityMonitor *monitor = (SGReachabilityMonitor *)info;
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
    zeroAddr.sin_len    = sizeof(zeroAddr);
    zeroAddr.sin_family = AF_INET;

    _reachabilityRef = SCNetworkReachabilityCreateWithAddress(NULL, (const struct sockaddr *)&zeroAddr);
    if (!_reachabilityRef) return;

    SCNetworkReachabilityContext ctx = {0, (void *)self, SGReachabilityRetain, SGReachabilityRelease, NULL};
    if (!SCNetworkReachabilitySetCallback(_reachabilityRef, SGReachabilityCallback, &ctx)) {
        CFRelease(_reachabilityRef);
        _reachabilityRef = NULL;
        return;
    }

    /**
     * Use RunLoop scheduling rather than a dispatch queue.
     * SCNetworkReachabilitySetDispatchQueue fires an immediate "initial state" callback
     * on assignment — before CFRunLoopRun() is entered — which races with configd's
     * WiFi state machine on iPod touch (WiFi-only devices). That race manifests as the
     * Settings WiFi toggle appearing grayed out or showing an inconsistent state when
     * the daemon is enabled while offline.
     *
     * RunLoop scheduling defers all callbacks to CFRunLoopRun(), ensuring they only
     * fire after startup is fully complete and Settings.app has finished its transition.
     */
    SCNetworkReachabilityScheduleWithRunLoop(_reachabilityRef, CFRunLoopGetMain(), kCFRunLoopDefaultMode);
}

- (void)stopMonitoringSystemNetworkChanges {
    if (_reachabilityRef) {
        SCNetworkReachabilityUnscheduleFromRunLoop(_reachabilityRef, CFRunLoopGetMain(), kCFRunLoopDefaultMode);
        SCNetworkReachabilitySetCallback(_reachabilityRef, NULL, NULL);
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
    /* kSCNetworkReachabilityFlagsIsWWAN is never set on WiFi-only devices (e.g. iPod touch). */
    return (flags & kSCNetworkReachabilityFlagsIsWWAN);
}

@end