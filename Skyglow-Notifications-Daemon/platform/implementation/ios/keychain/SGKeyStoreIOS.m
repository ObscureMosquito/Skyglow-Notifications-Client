#import "SGKeyStoreIOS.h"
#import <Security/Security.h>

static NSString * const kSGKeychainService = @"com.skyglow.daemon.privatekey";

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static id SGPreUnlockAccessibility(void) {
    return (__bridge id)kSecAttrAccessibleAlwaysThisDeviceOnly;
}
#pragma clang diagnostic pop

static NSString *SGAccountForIndex(NSInteger profileIndex) {
    return [NSString stringWithFormat:@"profile%ld", (long)profileIndex];
}

static NSMutableDictionary *SGBaseQuery(NSInteger profileIndex) {
    NSMutableDictionary *q = [NSMutableDictionary dictionary];
    [q setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
    [q setObject:kSGKeychainService forKey:(__bridge id)kSecAttrService];
    [q setObject:SGAccountForIndex(profileIndex) forKey:(__bridge id)kSecAttrAccount];
    return q;
}

@implementation SGKeyStoreIOS

- (BOOL)storeKeyData:(NSData *)pemData forProfile:(NSInteger)profileIndex {
    if (!pemData || [pemData length] == 0) return NO;

    NSMutableDictionary *attributes = [NSMutableDictionary dictionary];
    [attributes setObject:pemData forKey:(__bridge id)kSecValueData];
    [attributes setObject:SGPreUnlockAccessibility() forKey:(__bridge id)kSecAttrAccessible];

    NSMutableDictionary *query = SGBaseQuery(profileIndex);
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query,
                                    (__bridge CFDictionaryRef)attributes);
    if (status != errSecSuccess) {
        if (status != errSecItemNotFound) {
            SecItemDelete((__bridge CFDictionaryRef)query);
        }
        NSMutableDictionary *addQuery = SGBaseQuery(profileIndex);
        [addQuery addEntriesFromDictionary:attributes];
        status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
    }
    return (status == errSecSuccess);
}

- (BOOL)copyKeyData:(NSMutableData **)outPEMData forProfile:(NSInteger)profileIndex {
    if (outPEMData) *outPEMData = nil;
    NSMutableDictionary *query = SGBaseQuery(profileIndex);
    [query setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnData];
    [query setObject:(__bridge id)kSecMatchLimitOne forKey:(__bridge id)kSecMatchLimit];

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecItemNotFound) return YES;
    if (status != errSecSuccess || !result) return NO;

    NSData *data = [(NSData *)result autorelease];
    if (![data isKindOfClass:[NSData class]] || [data length] == 0) return NO;

    if (outPEMData) *outPEMData = [NSMutableData dataWithData:data];
    return YES;
}

- (BOOL)rewrapKeyForPreUnlockAccessForProfile:(NSInteger)profileIndex found:(BOOL *)outFound {
    if (outFound) *outFound = NO;
    NSMutableDictionary *query = SGBaseQuery(profileIndex);
    [query setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnData];
    [query setObject:(__bridge id)kSecMatchLimitOne forKey:(__bridge id)kSecMatchLimit];

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecItemNotFound) return YES;
    if (status != errSecSuccess || !result) return NO;

    NSData *data = [(NSData *)result autorelease];
    if (![data isKindOfClass:[NSData class]] || [data length] == 0) return NO;
    if (outFound) *outFound = YES;

    NSMutableDictionary *attributes = [NSMutableDictionary dictionary];
    /* Including the value also satisfies iOS 4's accessibility-update rule. */
    [attributes setObject:data forKey:(__bridge id)kSecValueData];
    [attributes setObject:SGPreUnlockAccessibility() forKey:(__bridge id)kSecAttrAccessible];

    NSMutableDictionary *updateQuery = SGBaseQuery(profileIndex);
    return SecItemUpdate((__bridge CFDictionaryRef)updateQuery,
                         (__bridge CFDictionaryRef)attributes) == errSecSuccess;
}

- (BOOL)deleteKeyForProfile:(NSInteger)profileIndex {
    NSMutableDictionary *query = SGBaseQuery(profileIndex);
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    return (status == errSecSuccess || status == errSecItemNotFound);
}

@end
