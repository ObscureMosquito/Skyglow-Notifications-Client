#ifndef SKYGLOW_SG_KEYCHAIN_STORE_H
#define SKYGLOW_SG_KEYCHAIN_STORE_H

#import <Foundation/Foundation.h>

/**
 * Thin wrapper over Security framework SecItem* APIs for storing the
 * per-profile RSA private key.  Keychain replaces the legacy on-disk PEM
 * file: storage location is no longer a daemon-constructed filesystem
 * path (eliminating any current or future path-traversal surface from
 * server-supplied identifiers), and the entry is encrypted at rest by
 * iOS using a device-derived key.
 *
 * Items use kSecClassGenericPassword with:
 *   service = "com.skyglow.daemon.privatekey"
 *   account = "profile<idx>"   (idx is 1..5)
 *   data    = UTF-8 PEM bytes
 *   access  = kSecAttrAccessibleAfterFirstUnlock
 *
 * AfterFirstUnlock lets the daemon read the key after the device has
 * been unlocked at least once since boot, including while the screen is
 * locked again later — required for background push delivery.
 *
 * All functions are thread-safe (SecItem APIs serialise internally).
 */

/** Store the PEM-encoded RSA private key for the given profile slot.
 *  Overwrites any existing entry.  Returns YES on success. */
BOOL SGKeychain_StorePrivateKeyPEM(NSString *pem, NSInteger profileIndex);

/** Retrieve the PEM-encoded RSA private key for the given profile slot.
 *  Returns nil if absent or on error. */
NSString *SGKeychain_FetchPrivateKeyPEM(NSInteger profileIndex);

/** Delete the keychain entry for the given profile slot.  Returns YES
 *  on success or if the entry was already absent. */
BOOL SGKeychain_DeletePrivateKey(NSInteger profileIndex);

#endif
