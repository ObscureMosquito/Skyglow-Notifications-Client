#ifndef SKYGLOW_NETWORK_MONITOR_H
#define SKYGLOW_NETWORK_MONITOR_H

#import <Foundation/Foundation.h>
#import <SystemConfiguration/SystemConfiguration.h>

typedef void (^NetworkReachabilityChangeBlock)(BOOL isReachable, BOOL isWWAN);

@interface NetworkMonitor : NSObject

- (instancetype)initWithCallback:(NetworkReachabilityChangeBlock)callback;
- (void)startMonitoring;
- (void)stopMonitoring;

@property (nonatomic, readonly) BOOL isReachable;
@property (nonatomic, readonly) BOOL isWWAN;

@end

#endif /* SKYGLOW_NETWORK_MONITOR_H */