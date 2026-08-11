#ifndef SKYGLOW_SG_KEYCHAIN_STORE_H
#define SKYGLOW_SG_KEYCHAIN_STORE_H

#import <Foundation/Foundation.h>

BOOL SGKeychain_StorePrivateKeyPEM(NSString *pem, NSInteger profileIndex);

/** Byte-preserving form for rollback without creating an immutable NSString. */
BOOL SGKeychain_StorePrivateKeyData(NSData *pemData, NSInteger profileIndex);

NSData *SGKeychain_FetchPrivateKeyPEM(NSInteger profileIndex);

/** Distinguishes a missing entry (YES with nil data) from a keychain failure. */
BOOL SGKeychain_CopyPrivateKeyPEM(NSInteger profileIndex,
                                  NSMutableData **outPEMData);

/** Missing item is success with outFound=NO. */
BOOL SGKeychain_RewrapPrivateKeyForPreUnlockAccess(NSInteger profileIndex,
                                                   BOOL *outFound);

BOOL SGKeychain_DeletePrivateKey(NSInteger profileIndex);

#endif
