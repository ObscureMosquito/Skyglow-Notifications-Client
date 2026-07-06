#import "SGTokenManager.h"
#import "SGDatabaseManager.h"
#import "SGConfiguration.h"
#import "SGProtocolHandler.h"
#import "SGCryptoEngine.h"
#import "SGLog.h"
#include <Security/Security.h>
#include <CommonCrypto/CommonDigest.h>

@interface SGTokenManager ()
- (NSData *)_generateTokenLocallyForBundleIdentifier:(NSString *)bundleIdentifier
                                                error:(NSError **)outError;
@end

@implementation SGTokenManager

- (NSData *)synchronizedTokenForBundleIdentifier:(NSString *)bundleIdentifier error:(NSError **)outError {
    @synchronized([SGTokenManager class]) {
        if (!bundleIdentifier || [bundleIdentifier length] == 0) {
            if (outError) *outError = [NSError errorWithDomain:@"com.skyglow.tokens" code:10 userInfo:nil];
            return nil;
        }

        NSArray *existing = [[SGDatabaseManager sharedManager] tokenEntriesForBundleIdentifier:bundleIdentifier];
        if ([existing count] > 0) {
            NSData *token = existing[0][@"token"];
            if (token && [token length] > 0) return [[token retain] autorelease];
        }

        return [self _generateTokenLocallyForBundleIdentifier:bundleIdentifier error:outError];
    }
}

- (NSData *)generateTokenLocallyForBundleIdentifier:(NSString *)bundleIdentifier error:(NSError **)outError {
    @synchronized([SGTokenManager class]) {
        return [self _generateTokenLocallyForBundleIdentifier:bundleIdentifier error:outError];
    }
}

- (NSData *)_generateTokenLocallyForBundleIdentifier:(NSString *)bundleIdentifier error:(NSError **)outError {
    if (outError) *outError = nil;
    NSString *serverAddr = [[SGConfiguration sharedConfiguration] serverAddress];
    NSData *addrData = [serverAddr dataUsingEncoding:NSUTF8StringEncoding];
    if (!serverAddr || [addrData length] == 0 ||
        [addrData length] > SGP_SERVER_ADDRESS_MAX_BYTES) {
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
    if ([e2eeKey length] != 32) {
        memset(K, 0, sizeof(K));
        if (outError) *outError = [NSError errorWithDomain:@"com.skyglow.tokens" code:13 userInfo:nil];
        return nil;
    }

    NSMutableData *deviceToken = [[NSMutableData alloc] initWithLength:32];
    uint8_t *ptr = [deviceToken mutableBytes];
    memset(ptr, 0, 32);
    memcpy(ptr, [addrData bytes], [addrData length]);
    memcpy(ptr + 16, K, 16);

    BOOL stored = [[SGDatabaseManager sharedManager] storeDeviceTokenData:routingKey
                                                                  e2eeKey:e2eeKey
                                                                 bundleID:bundleIdentifier
                                                                    token:deviceToken];

    memset(K, 0, sizeof(K));
    if (!stored) {
        if (outError) *outError = [NSError errorWithDomain:@"com.skyglow.tokens" code:14 userInfo:nil];
        [deviceToken release];
        SGLOGE(SGTokenManager, "code=%s bundle=%s result=failed reason=database_write",
               SGND_TOKEN_GENERATE_FAILED, [bundleIdentifier UTF8String]);
        return nil;
    }

    SGLOGI(SGTokenManager, "code=%s bundle=%s result=generated", SGND_TOKEN_GENERATED, [bundleIdentifier UTF8String]);
    return [deviceToken autorelease];
}

@end
