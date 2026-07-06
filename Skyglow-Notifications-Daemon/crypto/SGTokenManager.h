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
 * Generates and stores a token locally with no network I/O.  The server picks
 * the new binding up on the next SGP_FlushActiveTopicFilter (immediate when
 * connected, on next reconnect otherwise — the filter is a full-replace, so
 * unconnected adds are not lost).
 */
- (NSData *)generateTokenLocallyForBundleIdentifier:(NSString *)bundleIdentifier
                                              error:(NSError **)outError;

@end

#endif