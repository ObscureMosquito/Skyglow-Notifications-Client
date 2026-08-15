#import "SGReachabilityMonitor.h"
#import <SystemConfiguration/SystemConfiguration.h>
#include <netinet/in.h>

@implementation SGReachabilityMonitor {
    SCNetworkReachabilityRef _reachabilityRef;
    SGNetworkChangeHandler _handler;
}

static const void *SGReachabilityRetain(const void *info) {
    return [(SGReachabilityMonitor *)info retain];
}
static void SGReachabilityRelease(const void *info) {
    [(SGReachabilityMonitor *)info release];
}

static BOOL SGFlagsReachable(SCNetworkReachabilityFlags flags) {
    return (flags & kSCNetworkFlagsReachable) && !(flags & kSCNetworkFlagsConnectionRequired);
}

static void SGReachabilityCallback(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags flags, void *info) {
    SGReachabilityMonitor *monitor = (SGReachabilityMonitor *)info;
    if (monitor->_handler) {
        monitor->_handler(SGFlagsReachable(flags), [monitor flagsIndicateCellular:flags]);
    }
}

- (void)dealloc {
    [self stopMonitoring];
    [_handler release];
    [super dealloc];
}

- (BOOL)flagsIndicateCellular:(uint32_t)flags {
    (void)flags;
    return NO;
}

- (void)startMonitoringWithHandler:(SGNetworkChangeHandler)handler {
    if (_reachabilityRef) return;
    [_handler release];
    _handler = [handler copy];

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

    SCNetworkReachabilityScheduleWithRunLoop(_reachabilityRef, CFRunLoopGetMain(), kCFRunLoopDefaultMode);
}

- (void)stopMonitoring {
    if (_reachabilityRef) {
        SCNetworkReachabilityUnscheduleFromRunLoop(_reachabilityRef, CFRunLoopGetMain(), kCFRunLoopDefaultMode);
        SCNetworkReachabilitySetCallback(_reachabilityRef, NULL, NULL);
        CFRelease(_reachabilityRef);
        _reachabilityRef = NULL;
    }
}

- (SCNetworkReachabilityFlags)_currentFlags {
    SCNetworkReachabilityFlags flags = 0;
    if (_reachabilityRef) SCNetworkReachabilityGetFlags(_reachabilityRef, &flags);
    return flags;
}

- (BOOL)isReachable {
    return SGFlagsReachable([self _currentFlags]);
}

- (BOOL)activePathIsCellular {
    return [self flagsIndicateCellular:[self _currentFlags]];
}

@end
