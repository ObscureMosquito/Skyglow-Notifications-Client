#ifndef SKYGLOW_SG_KEYCHAIN_STORE_H
#define SKYGLOW_SG_KEYCHAIN_STORE_H

#import <Foundation/Foundation.h>

/**
 * Thin wrapper over Security framework SecItem* APIs for storing the
 * per-profile RSA private key. On iOS the credential is device-bound but
 * intentionally available before first unlock so the daemon can reconnect
 * immediately after boot.
 */

/* Store the PEM-encoded RSA private key for the given profile slot */
BOOL SGKeychain_StorePrivateKeyPEM(NSString *pem, NSInteger profileIndex);

/*
 * Byte-preserving form used for rollback without creating an immutable
 * NSString containing private-key material.
 */
BOOL SGKeychain_StorePrivateKeyData(NSData *pemData, NSInteger profileIndex);

/*
 * Retrieve the PEM-encoded RSA private key for the given profile slot as a
 * mutable, zeroable NSData
 */
NSData *SGKeychain_FetchPrivateKeyPEM(NSInteger profileIndex);

/** Distinguishes a missing entry (YES with nil data) from a keychain failure. */
BOOL SGKeychain_CopyPrivateKeyPEM(NSInteger profileIndex,
                                  NSMutableData **outPEMData);

/* Rewraps an existing item into the daemon's pre-unlock accessibility class.
 * This is a storage primitive; one-shot policy and versioning live in
 * SGMigration. A missing item is success with outFound=NO. */
BOOL SGKeychain_RewrapPrivateKeyForPreUnlockAccess(NSInteger profileIndex,
                                                   BOOL *outFound);

/* Delete the keychain entry for the given profile slot */
BOOL SGKeychain_DeletePrivateKey(NSInteger profileIndex);

#endif
