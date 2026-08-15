#ifndef SKYGLOW_SG_REACHABILITY_MONITOR_H
#define SKYGLOW_SG_REACHABILITY_MONITOR_H

#import "network/SGNetworkInfo.h"

/** SCNetworkReachability logic shared by every platform, thanks apple :) */
@interface SGReachabilityMonitor : NSObject <SGNetworkInfo>
- (BOOL)flagsIndicateCellular:(uint32_t)flags;
@end

#endif
