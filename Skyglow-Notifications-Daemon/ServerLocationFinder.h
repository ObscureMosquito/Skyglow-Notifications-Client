#ifndef SKYGLOW_SERVER_LOCATION_FINDER_H
#define SKYGLOW_SERVER_LOCATION_FINDER_H

#import <Foundation/Foundation.h>

@interface ServerLocationFinder : NSObject

+ (NSDictionary *)resolveServerLocation:(NSString *)serverAddr;
+ (void)refreshDNSCacheAsync:(NSString *)serverAddr;

@end

#endif /* SKYGLOW_SERVER_LOCATION_FINDER_H */