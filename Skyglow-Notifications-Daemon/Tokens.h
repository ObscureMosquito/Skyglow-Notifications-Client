#ifndef SKYGLOW_TOKENS_H
#define SKYGLOW_TOKENS_H

#include "DBManager.h"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <CommonCrypto/CommonDigest.h>
#include "Protocol.h"
#import "CryptoManager.h"
#import "TweakMachMessages.h"

@interface Tokens : NSObject

/// Returns a cached or freshly-generated device token for the given bundle ID.
/// On failure, returns nil and sets *outError (if outError is non-NULL).
- (NSData *)getDeviceToken:(NSString *)bundleID error:(NSError **)outError;

/// Removes all tokens for the given bundle ID and notifies the server.
- (BOOL)removeDeviceTokenForBundleId:(NSString *)bundleId reason:(NSString *)reason;

@end

#endif /* SKYGLOW_TOKENS_H */