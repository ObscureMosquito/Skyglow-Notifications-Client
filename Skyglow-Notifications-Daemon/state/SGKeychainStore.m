#import "SGKeychainStore.h"
#import <Security/Security.h>
#include <TargetConditionals.h>

static NSString * const kSGKeychainService = @"com.skyglow.daemon.privatekey";

#if TARGET_OS_IPHONE
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static id SGKeychain_PreUnlockAccessibility(void) {
    return (__bridge id)kSecAttrAccessibleAlwaysThisDeviceOnly;
}
#pragma clang diagnostic pop
#endif

static NSString *SGKeychain_AccountForIndex(NSInteger profileIndex) {
    return [NSString stringWithFormat:@"profile%ld", (long)profileIndex];
}

static NSMutableDictionary *SGKeychain_BaseQuery(NSInteger profileIndex) {
    NSMutableDictionary *q = [NSMutableDictionary dictionary];
    [q setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
    [q setObject:kSGKeychainService forKey:(__bridge id)kSecAttrService];
    [q setObject:SGKeychain_AccountForIndex(profileIndex) forKey:(__bridge id)kSecAttrAccount];
    return q;
}

BOOL SGKeychain_StorePrivateKeyPEM(NSString *pem, NSInteger profileIndex) {
    if (!pem || pem.length == 0) return NO;

    NSData *pemData = [pem dataUsingEncoding:NSUTF8StringEncoding];
    return SGKeychain_StorePrivateKeyData(pemData, profileIndex);
}

BOOL SGKeychain_StorePrivateKeyData(NSData *pemData, NSInteger profileIndex) {
    if (!pemData || [pemData length] == 0) return NO;

    NSMutableDictionary *attributes = [NSMutableDictionary dictionary];
    [attributes setObject:pemData forKey:(__bridge id)kSecValueData];
#if TARGET_OS_IPHONE
    /* Avoids passcode-keybag dependency so the daemon can auth before first unlock. */
    [attributes setObject:SGKeychain_PreUnlockAccessibility()
                   forKey:(__bridge id)kSecAttrAccessible];
#endif

    NSMutableDictionary *query = SGKeychain_BaseQuery(profileIndex);
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query,
                                    (__bridge CFDictionaryRef)attributes);
    if (status == errSecItemNotFound) {
        NSMutableDictionary *addQuery = SGKeychain_BaseQuery(profileIndex);
        [addQuery addEntriesFromDictionary:attributes];
        status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
    }
    return (status == errSecSuccess);
}

NSData *SGKeychain_FetchPrivateKeyPEM(NSInteger profileIndex) {
    NSMutableData *data = nil;
    return SGKeychain_CopyPrivateKeyPEM(profileIndex, &data) ? data : nil;
}

BOOL SGKeychain_CopyPrivateKeyPEM(NSInteger profileIndex,
                                  NSMutableData **outPEMData) {
    if (outPEMData) *outPEMData = nil;
    NSMutableDictionary *query = SGKeychain_BaseQuery(profileIndex);
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

BOOL SGKeychain_RewrapPrivateKeyForPreUnlockAccess(NSInteger profileIndex,
                                                   BOOL *outFound) {
    if (outFound) *outFound = NO;
#if !TARGET_OS_IPHONE
    return YES;
#else
    NSMutableDictionary *query = SGKeychain_BaseQuery(profileIndex);
    [query setObject:(__bridge id)kCFBooleanTrue
              forKey:(__bridge id)kSecReturnData];
    [query setObject:(__bridge id)kSecMatchLimitOne
              forKey:(__bridge id)kSecMatchLimit];

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query,
                                          &result);
    if (status == errSecItemNotFound) return YES;
    if (status != errSecSuccess || !result) return NO;

    NSData *data = [(NSData *)result autorelease];
    if (![data isKindOfClass:[NSData class]] || [data length] == 0) return NO;
    if (outFound) *outFound = YES;

    NSMutableDictionary *attributes = [NSMutableDictionary dictionary];
    /* Including the value also satisfies iOS 4's accessibility-update rule. */
    [attributes setObject:data forKey:(__bridge id)kSecValueData];
    [attributes setObject:SGKeychain_PreUnlockAccessibility()
                   forKey:(__bridge id)kSecAttrAccessible];

    NSMutableDictionary *updateQuery = SGKeychain_BaseQuery(profileIndex);
    return SecItemUpdate((__bridge CFDictionaryRef)updateQuery,
                         (__bridge CFDictionaryRef)attributes) == errSecSuccess;
#endif
}

BOOL SGKeychain_DeletePrivateKey(NSInteger profileIndex) {
    NSMutableDictionary *query = SGKeychain_BaseQuery(profileIndex);
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    return (status == errSecSuccess || status == errSecItemNotFound);
}
