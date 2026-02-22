#ifndef SKYGLOW_SG_SERVER_LOCATOR_H
#define SKYGLOW_SG_SERVER_LOCATOR_H

#import <Foundation/Foundation.h>

@interface SGServerLocator : NSObject

/**
 * Resolves the TCP endpoint (IP and Port) for a given server domain using DNS-SD TXT records.
 * Results are automatically cached in SGDatabaseManager for one hour.
 */
+ (NSDictionary *)resolveEndpointForServerAddress:(NSString *)serverAddress;

/**
 * Asynchronously refreshes the DNS cache for the specified server in the background.
 */
+ (void)refreshDNSCacheAsynchronouslyForAddress:(NSString *)serverAddress;

@end

#endif /* SKYGLOW_SG_SERVER_LOCATOR_H */