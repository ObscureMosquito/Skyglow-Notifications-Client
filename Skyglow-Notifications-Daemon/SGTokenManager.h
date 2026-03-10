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
 * Generates and stores a token locally with no network I/O.
 * Call uploadTokenIfNeededForBundleIdentifier: asynchronously to push to server.
 */
- (NSData *)generateTokenLocallyForBundleIdentifier:(NSString *)bundleIdentifier
                                              error:(NSError **)outError;

/**
 * Uploads the token to SGP server if not yet uploaded. Safe to call from any thread.
 */
- (void)uploadTokenIfNeededForBundleIdentifier:(NSString *)bundleIdentifier;

/**
 * Removes a token and triggers a bulk server filter update.
 */
- (BOOL)revokeTokenForBundleIdentifier:(NSString *)bundleIdentifier 
                                reason:(NSString *)reason;

@end

#endif