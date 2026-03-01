#ifndef SKYGLOW_SG_TOKEN_MANAGER_H
#define SKYGLOW_SG_TOKEN_MANAGER_H

#import <Foundation/Foundation.h>

@interface SGTokenManager : NSObject

/**
 * Retrieves a cached or newly generated push token for the specified app.
 */
- (NSData *)synchronizedTokenForBundleIdentifier:(NSString *)bundleIdentifier 
                                           error:(NSError **)outError;

/**
 * Removes a token and triggers a bulk server filter update.
 */
- (BOOL)revokeTokenForBundleIdentifier:(NSString *)bundleIdentifier 
                                reason:(NSString *)reason;

@end

#endif