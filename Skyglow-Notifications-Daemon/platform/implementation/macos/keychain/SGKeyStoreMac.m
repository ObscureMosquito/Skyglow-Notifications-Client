#import "SGKeyStoreMac.h"
#import "SGConfiguration.h"
#import "SGLog.h"
#import <Security/Security.h>

static NSString * const kSGKeychainService = @"com.skyglow.daemon.privatekey";

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

static SecKeychainRef SGSystemKeychain(void) {
    static SecKeychainRef sKeychain = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        SecKeychainSetUserInteractionAllowed(FALSE);
        SecKeychainRef kc = NULL;
        OSStatus status = SecKeychainOpen("/Library/Keychains/System.keychain", &kc);
        if (status == errSecSuccess && kc) {
            sKeychain = kc;
        } else {
            SGLOGE(SGKeyStore, "op=open status=%d result=failed", (int)status);
        }
    });
    return sKeychain;
}

static NSString *SGAccountForIndex(NSInteger profileIndex) {
    return [NSString stringWithFormat:@"profile%ld", (long)profileIndex];
}

static NSMutableDictionary *SGBaseQuery(NSInteger profileIndex) {
    NSMutableDictionary *q = [NSMutableDictionary dictionary];
    [q setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
    [q setObject:kSGKeychainService forKey:(__bridge id)kSecAttrService];
    [q setObject:SGAccountForIndex(profileIndex) forKey:(__bridge id)kSecAttrAccount];
    SecKeychainRef kc = SGSystemKeychain();
    if (kc) {
        [q setObject:[NSArray arrayWithObject:(__bridge id)kc] forKey:(__bridge id)kSecMatchSearchList];
    }
    return q;
}

static SecAccessRef SGCreateAnyApplicationAccess(void) {
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

@implementation SGKeyStoreMac

- (BOOL)storeKeyData:(NSData *)pemData forProfile:(NSInteger)profileIndex {
    if (!pemData || [pemData length] == 0 || !SGProfileIndexIsValid(profileIndex)) return NO;

    SecItemDelete((__bridge CFDictionaryRef)SGBaseQuery(profileIndex));

    NSMutableDictionary *addQuery = [NSMutableDictionary dictionary];
    [addQuery setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
    [addQuery setObject:kSGKeychainService forKey:(__bridge id)kSecAttrService];
    [addQuery setObject:SGAccountForIndex(profileIndex) forKey:(__bridge id)kSecAttrAccount];
    [addQuery setObject:pemData forKey:(__bridge id)kSecValueData];
    SecKeychainRef kc = SGSystemKeychain();
    if (kc) {
        [addQuery setObject:(__bridge id)kc forKey:(__bridge id)kSecUseKeychain];
    }
    SecAccessRef access = SGCreateAnyApplicationAccess();
    if (access) {
        [addQuery setObject:(__bridge id)access forKey:(__bridge id)kSecAttrAccess];
    }

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
    if (status != errSecSuccess) {
        SGLOGE(SGKeyStore, "op=add status=%d result=failed", (int)status);
    }
    if (access) CFRelease(access);
    return (status == errSecSuccess);
}

- (BOOL)copyKeyData:(NSMutableData **)outPEMData forProfile:(NSInteger)profileIndex {
    if (outPEMData) *outPEMData = nil;
    if (!SGProfileIndexIsValid(profileIndex)) return NO;

    NSMutableDictionary *query = SGBaseQuery(profileIndex);
    [query setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnData];
    [query setObject:(__bridge id)kSecMatchLimitOne forKey:(__bridge id)kSecMatchLimit];

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecItemNotFound) return YES;
    if (status != errSecSuccess || !result) {
        SGLOGE(SGKeyStore, "op=copy status=%d result=failed", (int)status);
        return NO;
    }

    NSData *data = [(NSData *)result autorelease];
    if (![data isKindOfClass:[NSData class]] || [data length] == 0) return NO;

    if (outPEMData) *outPEMData = [NSMutableData dataWithData:data];
    return YES;
}

- (BOOL)rewrapKeyForPreUnlockAccessForProfile:(NSInteger)profileIndex found:(BOOL *)outFound {
    if (outFound) *outFound = NO;
    return YES;
}

- (BOOL)deleteKeyForProfile:(NSInteger)profileIndex {
    if (!SGProfileIndexIsValid(profileIndex)) return NO;
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)SGBaseQuery(profileIndex));
    return (status == errSecSuccess || status == errSecItemNotFound);
}

@end

#pragma clang diagnostic pop
