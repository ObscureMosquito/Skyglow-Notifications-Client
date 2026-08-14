#ifndef SKYGLOW_SG_REACHABILITY_MONITOR_H
#define SKYGLOW_SG_REACHABILITY_MONITOR_H

#import <Foundation/Foundation.h>

typedef void (^SGReachabilityChangeHandler)(BOOL isReachable, BOOL isWWAN);

@interface SGReachabilityMonitor : NSObject

@property (nonatomic, readonly) BOOL isReachable;

- (instancetype)initWithChangeHandler:(SGReachabilityChangeHandler)handler;
- (void)startMonitoringSystemNetworkChanges;
- (void)stopMonitoringSystemNetworkChanges;

@end

#endif
