#import "Tokens.h"
#import "Globals.h"
#import "Protocol.h"
#import "CryptoManager.h"
#include <Security/Security.h>
#include <CommonCrypto/CommonDigest.h>

@implementation Tokens

- (NSData *)getDeviceToken:(NSString *)bundleID error:(NSError **)outError {
    if (!bundleID || [bundleID length] == 0) {
        if (outError) *outError = [NSError errorWithDomain:@"SkyglowTokens"
                                                      code:10
                                                  userInfo:@{NSLocalizedDescriptionKey: @"Empty bundle ID"}];
        return nil;
    }

    NSArray *existing = [db dataForBundleID:bundleID];
    if ([existing count] > 0) {
        NSData *token = existing[0][@"token"];
        if (token && [token length] > 0) {
            return token;
        }
    }
    return [self generateDeviceToken:bundleID error:outError];
}

- (BOOL)removeDeviceTokenForBundleId:(NSString *)bundleId reason:(NSString *)reason {
    if (!bundleId) return NO;

    // 1. Delete the tokens from the local database
    [db removeTokenWithBundleId:bundleId];
    
    // 2. Trigger the bulk topic filter. 
    // If we are connected, this tells the server the app is gone immediately.
    // If we are offline, this safely does nothing (it will sync automatically on next connect).
    flushActiveTopicFilter();
    
    return YES;
}

- (NSData *)generateDeviceToken:(NSString *)bundleID error:(NSError **)outError {
    NSLog(@"[Tokens] Generating device token for %@", bundleID);
    
    // Dynamically fetch the server address safely
    NSString *currentServerAddr = GetServerAddress();
    if (!currentServerAddr) {
        if (outError) *outError = [NSError errorWithDomain:@"SkyglowTokens"
                                                      code:11
                                                  userInfo:@{NSLocalizedDescriptionKey: @"Daemon not configured with a server address"}];
        return nil;
    }

    // 1. Generate 16 random bytes (K)
    uint8_t K[16];
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(K), K) != errSecSuccess) {
        if (outError) *outError = [NSError errorWithDomain:@"SkyglowTokens"
                                                      code:1
                                                  userInfo:@{NSLocalizedDescriptionKey: @"SecRandomCopyBytes failed"}];
        return nil;
    }

    // 2. Routing key = SHA-256(K)
    unsigned char hashBuf[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(K, sizeof(K), hashBuf);
    NSData *routingKey = [NSData dataWithBytes:hashBuf length:CC_SHA256_DIGEST_LENGTH];

    // 3. E2EE key via HKDF
    NSString *hkdfSalt = [NSString stringWithFormat:@"%@%@",
                          currentServerAddr, @"Hello from the Skyglow Notifications developers!"];
    NSData *keyMaterial = [NSData dataWithBytes:K length:sizeof(K)];
    NSData *e2eeKey = deriveE2EEKey(keyMaterial, hkdfSalt, 32);
    if (!e2eeKey) {
        if (outError) *outError = [NSError errorWithDomain:@"SkyglowTokens"
                                                      code:4
                                                  userInfo:@{NSLocalizedDescriptionKey: @"HKDF derivation failed"}];
        return nil;
    }

    // 4. Build the device token: [serverAddr padded to 16 bytes] || K
    NSData *serverAddrData = [currentServerAddr dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *paddedAddr = [NSMutableData dataWithLength:16];
    memset([paddedAddr mutableBytes], 0, 16);
    NSUInteger copyLen = MIN([serverAddrData length], (NSUInteger)16);
    memcpy([paddedAddr mutableBytes], [serverAddrData bytes], copyLen);

    NSMutableData *deviceKey = [NSMutableData dataWithCapacity:32];
    [deviceKey appendData:paddedAddr];
    [deviceKey appendBytes:K length:sizeof(K)];

    // 5. Register routing key with the server if connected, otherwise defer.
    BOOL uploaded = NO;

    if (!isConnected()) {
        NSLog(@"[Tokens] Not connected — storing token locally for deferred upload");
    } else if (!registerDeviceToken(routingKey, bundleID)) {
        NSLog(@"[Tokens] Server did not acknowledge token registration — storing for deferred upload");
    } else {
        uploaded = YES;
    }

    // 6. Persist locally (always — even if upload failed/deferred)
    if (![db storeTokenData:routingKey e2eeKey:e2eeKey bundleID:bundleID token:deviceKey
                 isUploaded:uploaded]) {
        if (outError) *outError = [NSError errorWithDomain:@"SkyglowTokens"
                                                      code:2
                                                  userInfo:@{NSLocalizedDescriptionKey: @"Database store failed"}];
        return nil;
    }

    if (uploaded) {
        NSLog(@"[Tokens] Successfully generated and uploaded token for %@", bundleID);
    } else {
        NSLog(@"[Tokens] Token stored locally for %@ — will upload when connected", bundleID);
    }
    return deviceKey;
}

@end