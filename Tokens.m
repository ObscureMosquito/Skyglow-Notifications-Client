#import "Tokens.h"
#import "Globals.h"
#include <Security/Security.h>

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

    NSArray *entries = [db dataForBundleID:bundleId];
    for (NSDictionary *entry in entries) {
        NSData *routingKey = entry[@"routingKey"];
        if (routingKey) {
            sendFeedback(routingKey, @0, reason ?: @"");
        }
    }

    [db removeTokenWithBundleId:bundleId];
    return YES;
}

- (NSData *)generateDeviceToken:(NSString *)bundleID error:(NSError **)outError {
    NSLog(@"[Tokens] Generating device token for %@", bundleID);

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
                          serverAddress, @"Hello from the Skyglow Notifications developers!"];
    NSData *keyMaterial = [NSData dataWithBytes:K length:sizeof(K)];
    NSData *e2eeKey = deriveE2EEKey(keyMaterial, hkdfSalt, 32);
    if (!e2eeKey) {
        if (outError) *outError = [NSError errorWithDomain:@"SkyglowTokens"
                                                      code:4
                                                  userInfo:@{NSLocalizedDescriptionKey: @"HKDF derivation failed"}];
        return nil;
    }

    // 4. Build the device token: [serverAddr padded to 16 bytes] || K
    NSData *serverAddrData = [serverAddress dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *paddedAddr = [NSMutableData dataWithLength:16];
    memset([paddedAddr mutableBytes], 0, 16);
    NSUInteger copyLen = MIN([serverAddrData length], (NSUInteger)16);
    memcpy([paddedAddr mutableBytes], [serverAddrData bytes], copyLen);

    NSMutableData *deviceKey = [NSMutableData dataWithCapacity:32];
    [deviceKey appendData:paddedAddr];
    [deviceKey appendBytes:K length:sizeof(K)];

    // 5. Register routing key with the server (blocks up to 5 s)
    if (!isConnected()) {
        if (outError) *outError = [NSError errorWithDomain:@"SkyglowTokens"
                                                      code:5
                                                  userInfo:@{NSLocalizedDescriptionKey: @"Not connected to server"}];
        return nil;
    }

    if (!registerDeviceToken(routingKey, bundleID)) {
        NSLog(@"[Tokens] Server did not acknowledge token registration");
        if (outError) *outError = [NSError errorWithDomain:@"SkyglowTokens"
                                                      code:3
                                                  userInfo:@{NSLocalizedDescriptionKey: @"Token registration ack timeout"}];
        return nil;
    }

    // 6. Persist locally
    if (![db storeTokenData:routingKey e2eeKey:e2eeKey bundleID:bundleID token:deviceKey]) {
        if (outError) *outError = [NSError errorWithDomain:@"SkyglowTokens"
                                                      code:2
                                                  userInfo:@{NSLocalizedDescriptionKey: @"Database store failed"}];
        return nil;
    }

    NSLog(@"[Tokens] Successfully generated token for %@", bundleID);
    return deviceKey;
}

@end