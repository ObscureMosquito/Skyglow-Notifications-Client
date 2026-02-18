#import "Tokens.h"
#import "Globals.h"
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

/// Read the device_address from the registration profile plist.
/// Returns nil if the device is not registered.
- (NSString *)readDeviceAddress {
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    return prefs[@"device_address"];
}

/// Compute the device routing ID: SHA256(device_address) truncated to 16 bytes.
/// This is what the server uses to route notifications to this device.
/// External services extract this from the token and include it when sending notifications.
- (NSData *)computeDeviceRoutingId:(NSString *)deviceAddress {
    if (!deviceAddress) return nil;

    NSData *addressData = [deviceAddress dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char hashBuf[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256([addressData bytes], (CC_LONG)[addressData length], hashBuf);

    // Truncate to first 16 bytes
    return [NSData dataWithBytes:hashBuf length:16];
}

- (NSData *)generateDeviceToken:(NSString *)bundleID error:(NSError **)outError {
    NSLog(@"[Tokens] Generating device token for %@", bundleID);

    // ── Validate prerequisites ──

    if (!serverAddress || [serverAddress length] == 0) {
        if (outError) *outError = [NSError errorWithDomain:@"SkyglowTokens"
                                                      code:6
                                                  userInfo:@{NSLocalizedDescriptionKey: @"Server address not configured"}];
        return nil;
    }

    NSString *deviceAddress = [self readDeviceAddress];
    if (!deviceAddress || [deviceAddress length] == 0) {
        if (outError) *outError = [NSError errorWithDomain:@"SkyglowTokens"
                                                      code:7
                                                  userInfo:@{NSLocalizedDescriptionKey: @"Device not registered (no device_address)"}];
        return nil;
    }

    // 1. Generate 16 random bytes (K) — the per-app secret
    uint8_t K[16];
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(K), K) != errSecSuccess) {
        if (outError) *outError = [NSError errorWithDomain:@"SkyglowTokens"
                                                      code:1
                                                  userInfo:@{NSLocalizedDescriptionKey: @"SecRandomCopyBytes failed"}];
        return nil;
    }

    // 2. Routing key = SHA-256(K) — used by the client to look up the right E2EE key
    //    when a notification arrives. Also included in the notification by the sender.
    unsigned char routingHashBuf[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(K, sizeof(K), routingHashBuf);
    NSData *routingKey = [NSData dataWithBytes:routingHashBuf length:CC_SHA256_DIGEST_LENGTH];

    // 3. E2EE key via HKDF — the per-app encryption key
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

    // 4. Compute device routing ID = SHA256(device_address)[:16]
    //    The server uses this to find the device's TCP connection.
    NSData *deviceRoutingId = [self computeDeviceRoutingId:deviceAddress];
    if (!deviceRoutingId || [deviceRoutingId length] != 16) {
        if (outError) *outError = [NSError errorWithDomain:@"SkyglowTokens"
                                                      code:8
                                                  userInfo:@{NSLocalizedDescriptionKey: @"Failed to compute device routing ID"}];
        return nil;
    }

    // 5. Build the device token:
    //    [server_addr padded to 16 bytes] || [device_routing_id 16 bytes] || [K 16 bytes] = 48 bytes
    //
    //    When an external service wants to send a notification:
    //    - Extract server_addr from bytes [0:16]  → determines which server to contact
    //    - Extract device_routing_id from [16:32]  → included in POST for routing
    //    - Extract K from bytes [32:48]            → derive E2EE key, compute routing_key = SHA256(K)
    NSMutableData *paddedAddr = [NSMutableData dataWithLength:16];
    memset([paddedAddr mutableBytes], 0, 16);
    NSData *serverAddrData = [serverAddress dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger copyLen = MIN([serverAddrData length], (NSUInteger)16);
    memcpy([paddedAddr mutableBytes], [serverAddrData bytes], copyLen);

    NSMutableData *deviceToken = [NSMutableData dataWithCapacity:48];
    [deviceToken appendData:paddedAddr];          // bytes  0-15: server address
    [deviceToken appendData:deviceRoutingId];     // bytes 16-31: device routing ID
    [deviceToken appendBytes:K length:sizeof(K)]; // bytes 32-47: per-app secret K

    // 6. Persist locally — NO server round-trip needed!
    //    The server doesn't need to know about individual app tokens.
    //    It routes by device_routing_id (stored at device registration time).
    if (![db storeTokenData:routingKey e2eeKey:e2eeKey bundleID:bundleID token:deviceToken]) {
        if (outError) *outError = [NSError errorWithDomain:@"SkyglowTokens"
                                                      code:2
                                                  userInfo:@{NSLocalizedDescriptionKey: @"Database store failed"}];
        return nil;
    }

    NSLog(@"[Tokens] Successfully generated token for %@ (48 bytes, local-only)", bundleID);
    return deviceToken;
}

@end