#import "SGKeychainStore.h"
#import "SGConfiguration.h"
#import "SGLog.h"
#import <Security/Security.h>
#include <TargetConditionals.h>

#if TARGET_OS_OSX

static NSString * const kSGKeychainService = @"com.skyglow.daemon.privatekey";

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

static SecKeychainRef SGKeychain_SystemKeychain(void) {
    static SecKeychainRef sKeychain = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        SecKeychainSetUserInteractionAllowed(FALSE);
        SecKeychainRef kc = NULL;
        OSStatus status = SecKeychainOpen("/Library/Keychains/System.keychain", &kc);
        if (status == errSecSuccess && kc) {
            sKeychain = kc;
        } else {
            SGLOGE(SGKeychainStore, "op=open status=%d result=failed", (int)status);
        }
    });
    return sKeychain;
}

static NSString *SGKeychain_AccountForIndex(NSInteger profileIndex) {
    return [NSString stringWithFormat:@"profile%ld", (long)profileIndex];
}

static NSMutableDictionary *SGKeychain_BaseQuery(NSInteger profileIndex) {
    NSMutableDictionary *q = [NSMutableDictionary dictionary];
    [q setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
    [q setObject:kSGKeychainService forKey:(__bridge id)kSecAttrService];
    [q setObject:SGKeychain_AccountForIndex(profileIndex) forKey:(__bridge id)kSecAttrAccount];
    SecKeychainRef kc = SGKeychain_SystemKeychain();
    if (kc) {
        [q setObject:[NSArray arrayWithObject:(__bridge id)kc] forKey:(__bridge id)kSecMatchSearchList];
    }
    return q;
}

static SecAccessRef SGKeychain_CreateAnyApplicationAccess(void) {
    CSSM_LIST_ELEMENT anySubject;
    memset(&anySubject, 0, sizeof(anySubject));
    anySubject.ElementType = CSSM_LIST_ELEMENT_WORDID;
    anySubject.WordID = CSSM_ACL_SUBJECT_TYPE_ANY;

    CSSM_LIST subjectList;
    memset(&subjectList, 0, sizeof(subjectList));
    subjectList.ListType = CSSM_LIST_TYPE_UNKNOWN;
    subjectList.Head = subjectList.Tail = &anySubject;

    CSSM_ACL_OWNER_PROTOTYPE owner;
    memset(&owner, 0, sizeof(owner));
    owner.TypedSubject = subjectList;
    owner.Delegate = CSSM_FALSE;

    CSSM_ACL_AUTHORIZATION_TAG anyTag = CSSM_ACL_AUTHORIZATION_ANY;
    CSSM_ACL_ENTRY_INFO entry;
    memset(&entry, 0, sizeof(entry));
    entry.EntryPublicInfo.TypedSubject = subjectList;
    entry.EntryPublicInfo.Delegate = CSSM_FALSE;
    entry.EntryPublicInfo.Authorization.NumberOfAuthTags = 1;
    entry.EntryPublicInfo.Authorization.AuthTags = &anyTag;

    SecAccessRef access = NULL;
    OSStatus status = SecAccessCreateFromOwnerAndACL(&owner, 1, &entry, &access);
    return (status == errSecSuccess) ? access : NULL;
}

BOOL SGKeychain_StorePrivateKeyPEM(NSString *pem, NSInteger profileIndex) {
    if (!pem || pem.length == 0) return NO;
    NSData *pemData = [pem dataUsingEncoding:NSUTF8StringEncoding];
    return SGKeychain_StorePrivateKeyData(pemData, profileIndex);
}

BOOL SGKeychain_StorePrivateKeyData(NSData *pemData, NSInteger profileIndex) {
    if (!pemData || [pemData length] == 0 || !SGProfileIndexIsValid(profileIndex)) return NO;

    SecItemDelete((__bridge CFDictionaryRef)SGKeychain_BaseQuery(profileIndex));

    NSMutableDictionary *addQuery = [NSMutableDictionary dictionary];
    [addQuery setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
    [addQuery setObject:kSGKeychainService forKey:(__bridge id)kSecAttrService];
    [addQuery setObject:SGKeychain_AccountForIndex(profileIndex) forKey:(__bridge id)kSecAttrAccount];
    [addQuery setObject:pemData forKey:(__bridge id)kSecValueData];
    SecKeychainRef kc = SGKeychain_SystemKeychain();
    if (kc) {
        [addQuery setObject:(__bridge id)kc forKey:(__bridge id)kSecUseKeychain];
    }
    SecAccessRef access = SGKeychain_CreateAnyApplicationAccess();
    if (access) {
        [addQuery setObject:(__bridge id)access forKey:(__bridge id)kSecAttrAccess];
    }

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
    if (status != errSecSuccess) {
        SGLOGE(SGKeychainStore, "op=add status=%d result=failed", (int)status);
    }
    if (access) CFRelease(access);
    return (status == errSecSuccess);
}

NSData *SGKeychain_FetchPrivateKeyPEM(NSInteger profileIndex) {
    NSMutableData *data = nil;
    return SGKeychain_CopyPrivateKeyPEM(profileIndex, &data) ? data : nil;
}

BOOL SGKeychain_CopyPrivateKeyPEM(NSInteger profileIndex,
                                  NSMutableData **outPEMData) {
    if (outPEMData) *outPEMData = nil;
    if (!SGProfileIndexIsValid(profileIndex)) return NO;

    NSMutableDictionary *query = SGKeychain_BaseQuery(profileIndex);
    [query setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnData];
    [query setObject:(__bridge id)kSecMatchLimitOne forKey:(__bridge id)kSecMatchLimit];

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecItemNotFound) return YES;
    if (status != errSecSuccess || !result) {
        SGLOGE(SGKeychainStore, "op=copy status=%d result=failed", (int)status);
        return NO;
    }

    NSData *data = [(NSData *)result autorelease];
    if (![data isKindOfClass:[NSData class]] || [data length] == 0) return NO;

    if (outPEMData) *outPEMData = [NSMutableData dataWithData:data];
    return YES;
}

BOOL SGKeychain_RewrapPrivateKeyForPreUnlockAccess(NSInteger profileIndex,
                                                   BOOL *outFound) {
    if (outFound) *outFound = NO;
    return YES;
}

BOOL SGKeychain_DeletePrivateKey(NSInteger profileIndex) {
    if (!SGProfileIndexIsValid(profileIndex)) return NO;
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)SGKeychain_BaseQuery(profileIndex));
    return (status == errSecSuccess || status == errSecItemNotFound);
}

#pragma clang diagnostic pop

#else // TARGET_OS_IPHONE

static NSString * const kSGKeychainService = @"com.skyglow.daemon.privatekey";


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static id SGKeychain_PreUnlockAccessibility(void) {
    return (__bridge id)kSecAttrAccessibleAlwaysThisDeviceOnly;
}
#pragma clang diagnostic pop

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
    /* Avoids passcode-keybag dependency so the daemon can auth before first unlock. */
    [attributes setObject:SGKeychain_PreUnlockAccessibility()
                   forKey:(__bridge id)kSecAttrAccessible];

    NSMutableDictionary *query = SGKeychain_BaseQuery(profileIndex);
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query,
                                    (__bridge CFDictionaryRef)attributes);
    if (status != errSecSuccess) {
        if (status != errSecItemNotFound) {
            SecItemDelete((__bridge CFDictionaryRef)query);
        }
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
}

BOOL SGKeychain_DeletePrivateKey(NSInteger profileIndex) {
    NSMutableDictionary *query = SGKeychain_BaseQuery(profileIndex);
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    return (status == errSecSuccess || status == errSecItemNotFound);
}

#endif
