#import "Tokens.h"
#import "Globals.h"

@implementation Tokens

- (void)deviceTokenRegistrationCompleted:(NSString *)bundleId {
    if ([bundleId isEqualToString:_pendingBundleID]) {
        _tokenRegistrationCompleted = YES;
        dispatch_semaphore_signal(_tokenRegistrationSemaphore);
    }
}

- (NSData*)getDeviceToken:(NSString*)bundleID error:(NSError*)err { 
    NSArray *previousTokens = [db dataForBundleID:bundleID];
    if ([previousTokens count] == 0) {
        return [self generateDeviceToken:bundleID error:err];
    } else {
        return previousTokens[0][@"token"];
    }
}

- (NSData*)generateDeviceToken:(NSString*)bundleID error:(NSError*)err {
    NSLog(@"Generating Device Token");
    // Securely generate 16 bytes, (K in protocol)
    uint8_t K[16];
    int status = SecRandomCopyBytes(kSecRandomDefault, (sizeof K)/(sizeof K[0]), K);
    if (status != errSecSuccess) {
        err = [NSError errorWithDomain:@"Failed to generate secure secret!" code:1 userInfo:nil];
        return nil;
    }

    // create routing key
    unsigned char hashedValueChar[32];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, K, 16);
    SHA256_Final(hashedValueChar, &sha256);
    CC_SHA256(K, 16, hashedValueChar);    
    NSData *routingKey = [NSData dataWithBytes:hashedValueChar length:32];
    
    // create e2ee key
    NSString *hkdfSalt = [NSString stringWithFormat:@"%@%@", serverAddress, @"Hello from the Skyglow Notifications developers!"];
    NSData *keyMaterial = [NSData dataWithBytes:K length:sizeof(K)];
    NSData *e2eeKey = deriveE2EEKey(keyMaterial, hkdfSalt, 32);

    // create final device token
    NSData *serverAddrData = [serverAddress dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *paddedServerAddr = [NSMutableData dataWithCapacity:16];
    
    if (serverAddrData.length < 16) {
        // If server address is less than 16 bytes, add padding
        [paddedServerAddr appendData:serverAddrData];
        NSUInteger paddingNeeded = 16 - serverAddrData.length;
        uint8_t zeroPadding[paddingNeeded];
        memset(zeroPadding, 0, paddingNeeded); // Using zero as padding
        [paddedServerAddr appendBytes:zeroPadding length:paddingNeeded];
    } else if (serverAddrData.length > 16) {
        // smth has gone critially wrong.
        [paddedServerAddr appendBytes:[serverAddrData bytes] length:16];
    } else {
        // exactly 16 bytes
        [paddedServerAddr appendData:serverAddrData];
    }
    
    // Combine padded server address with K to ensure we have a 32-byte key
    NSMutableData *deviceKey = [NSMutableData dataWithData:paddedServerAddr];
    [deviceKey appendBytes:K length:16];

     // send to server
    BOOL didSucceed = registerDeviceToken(routingKey, bundleID);

    if (didSucceed == NO) {
        NSLog(@"Timeout waiting for token registration acknowledgment");
        err = [NSError errorWithDomain:@"Token registration acknowledgment timeout" code:3 userInfo:nil];
        return nil;
    }

    // store our key
    BOOL result = [db storeTokenData:routingKey e2eeKey:e2eeKey bundleID:bundleID token:deviceKey];
    if (!result) {
        err = [NSError errorWithDomain:@"Failed to store created token!" code:2 userInfo:nil];
        return nil;
    }
    
    return deviceKey;
}

@end