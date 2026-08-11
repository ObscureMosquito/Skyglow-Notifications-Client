#ifndef SKYGLOW_SG_SERVER_LOCATOR_H
#define SKYGLOW_SG_SERVER_LOCATOR_H

#import <Foundation/Foundation.h>

@interface SGServerLocator : NSObject

/** Resolves IP+port via DNS-SD TXT records; results cached for one hour. */
+ (NSDictionary *)resolveEndpointForServerAddress:(NSString *)serverAddress;

+ (void)refreshDNSCacheAsynchronouslyForAddress:(NSString *)serverAddress;

@end

#endif