#import "SGKeychainStore.h"
#import <Security/Security.h>

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
    if (!pemData) return NO;

    /* SecItemAdd refuses duplicates; SecItemUpdate refuses absent items.
     * Delete-then-add is the simplest race-free overwrite. */
    NSMutableDictionary *delQuery = SGKeychain_BaseQuery(profileIndex);
    SecItemDelete((__bridge CFDictionaryRef)delQuery);

    NSMutableDictionary *addQuery = SGKeychain_BaseQuery(profileIndex);
    [addQuery setObject:pemData forKey:(__bridge id)kSecValueData];
    /* AfterFirstUnlock so the headless daemon can read the key after a reboot
     * once the device has been unlocked once; ThisDeviceOnly so the private key
     * is never carried off-device in an encrypted backup or device migration. */
    [addQuery setObject:(__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                 forKey:(__bridge id)kSecAttrAccessible];

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
    return (status == errSecSuccess);
}

NSData *SGKeychain_FetchPrivateKeyPEM(NSInteger profileIndex) {
    NSMutableDictionary *query = SGKeychain_BaseQuery(profileIndex);
    [query setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnData];
    [query setObject:(__bridge id)kSecMatchLimitOne forKey:(__bridge id)kSecMatchLimit];

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status != errSecSuccess || !result) return nil;

    /* Return a mutable copy so the caller can zero the bytes when done — key
     * material must never be left in an immutable buffer we can't scrub. */
    NSData *data = [(NSData *)result autorelease];
    return [NSMutableData dataWithData:data];
}

BOOL SGKeychain_DeletePrivateKey(NSInteger profileIndex) {
    NSMutableDictionary *query = SGKeychain_BaseQuery(profileIndex);
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    return (status == errSecSuccess || status == errSecItemNotFound);
}
