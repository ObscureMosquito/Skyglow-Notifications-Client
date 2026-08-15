#ifndef SKYGLOW_SG_NETWORK_INFO_H
#define SKYGLOW_SG_NETWORK_INFO_H

#import <Foundation/Foundation.h>

typedef void (^SGNetworkChangeHandler)(BOOL reachable, BOOL activePathIsCellular);

@protocol SGNetworkInfo <NSObject>
- (void)startMonitoringWithHandler:(SGNetworkChangeHandler)handler;
- (void)stopMonitoring;
- (BOOL)isReachable;
- (BOOL)activePathIsCellular;
@end

#endif
