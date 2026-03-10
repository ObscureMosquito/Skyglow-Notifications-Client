#import "SGTokenManager.h"
#import "SGDatabaseManager.h"
#import "SGConfiguration.h"
#import "SGProtocolHandler.h"
#import "SGCryptoEngine.h"
#include <Security/Security.h>
#include <CommonCrypto/CommonDigest.h>

@implementation SGTokenManager

- (NSData *)synchronizedTokenForBundleIdentifier:(NSString *)bundleIdentifier error:(NSError **)outError {
    if (!bundleIdentifier || [bundleIdentifier length] == 0) {
        if (outError) *outError = [NSError errorWithDomain:@"com.skyglow.tokens" code:10 userInfo:nil];
        return nil;
    }

    NSArray *existing = [[SGDatabaseManager sharedManager] tokenEntriesForBundleIdentifier:bundleIdentifier];
    if ([existing count] > 0) {
        NSData *token = existing[0][@"token"];
        if (token && [token length] > 0) return [[token retain] autorelease];
    }

    return [self generateTokenLocallyForBundleIdentifier:bundleIdentifier error:outError];
}

- (BOOL)revokeTokenForBundleIdentifier:(NSString *)bundleIdentifier reason:(NSString *)reason {
    if (!bundleIdentifier) return NO;

    [[SGDatabaseManager sharedManager] removeTokenForBundleIdentifier:bundleIdentifier];
    SGP_FlushActiveTopicFilter();
    
    return YES;
}

- (NSData *)generateTokenLocallyForBundleIdentifier:(NSString *)bundleIdentifier error:(NSError **)outError {
    NSString *serverAddr = [[SGConfiguration sharedConfiguration] serverAddress];
    if (!serverAddr) {
        if (outError) *outError = [NSError errorWithDomain:@"com.skyglow.tokens" code:11 userInfo:nil];
        return nil;
    }

    uint8_t K[16];
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(K), K) != errSecSuccess) {
        if (outError) *outError = [NSError errorWithDomain:@"com.skyglow.tokens" code:12 userInfo:nil];
        return nil;
    }

    unsigned char hashBuf[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(K, sizeof(K), hashBuf);
    NSData *routingKey = [NSData dataWithBytes:hashBuf length:CC_SHA256_DIGEST_LENGTH];

    NSString *salt = [NSString stringWithFormat:@"%@Hello from the Skyglow Notifications developers!", serverAddr];
    NSData *e2eeKey = SG_CryptoDeriveE2EEKey([NSData dataWithBytes:K length:16], salt, 32);

    NSData *addrData = [serverAddr dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *deviceToken = [[NSMutableData alloc] initWithLength:32];
    uint8_t *ptr = [deviceToken mutableBytes];
    memset(ptr, 0, 32);
    memcpy(ptr, [addrData bytes], MIN([addrData length], (NSUInteger)16));
    memcpy(ptr + 16, K, 16);

    // Store with isUploaded=NO — server upload happens async via uploadTokenIfNeededForBundleIdentifier:
    [[SGDatabaseManager sharedManager] storeDeviceTokenData:routingKey
                                                   e2eeKey:e2eeKey
                                                  bundleID:bundleIdentifier
                                                     token:deviceToken
                                                isUploaded:NO];

    NSLog(@"[SGTokenManager] Generated local token for %@", bundleIdentifier);
    return [deviceToken autorelease];
}

- (void)uploadTokenIfNeededForBundleIdentifier:(NSString *)bundleIdentifier {
    NSArray *existing = [[SGDatabaseManager sharedManager] tokenEntriesForBundleIdentifier:bundleIdentifier];
    if (existing.count == 0) return;

    NSDictionary *entry = existing[0];
    if ([entry[@"isUploaded"] boolValue]) return;

    NSData *routingKey = entry[@"routingKey"];
    if (!routingKey) return;

    if (SGP_IsConnected() && SGP_RegisterDeviceToken(routingKey, bundleIdentifier)) {
        [[SGDatabaseManager sharedManager] markTokenAsUploaded:routingKey];
        NSLog(@"[SGTokenManager] Token uploaded for %@", bundleIdentifier);
    } else {
        NSLog(@"[SGTokenManager] Token upload deferred for %@ (not connected)", bundleIdentifier);
    }
}

@end