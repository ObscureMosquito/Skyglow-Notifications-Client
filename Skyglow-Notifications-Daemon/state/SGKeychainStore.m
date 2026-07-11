#import "SGKeychainStore.h"
#import <Security/Security.h>
#include <TargetConditionals.h>

static NSString * const kSGKeychainService = @"com.skyglow.daemon.privatekey";

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

    NSMutableDictionary *delQuery = SGKeychain_BaseQuery(profileIndex);
    SecItemDelete((__bridge CFDictionaryRef)delQuery);

    NSMutableDictionary *addQuery = SGKeychain_BaseQuery(profileIndex);
    [addQuery setObject:pemData forKey:(__bridge id)kSecValueData];
#if TARGET_OS_IPHONE
    [addQuery setObject:(__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                 forKey:(__bridge id)kSecAttrAccessible];
#endif

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
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
    if (outPEMData) *outPEMData = [NSMutableData dataWithData:data];
    return YES;
}

BOOL SGKeychain_DeletePrivateKey(NSInteger profileIndex) {
    NSMutableDictionary *query = SGKeychain_BaseQuery(profileIndex);
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    return (status == errSecSuccess || status == errSecItemNotFound);
}
