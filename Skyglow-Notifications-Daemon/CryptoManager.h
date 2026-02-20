#ifndef SKYGLOW_CRYPTOMANAGER_H
#define SKYGLOW_CRYPTOMANAGER_H

#import <Foundation/Foundation.h>
#import "openssl/evp.h"
#import "openssl/kdf.h"
#include <openssl/pem.h>
#include <openssl/err.h>

/// Derive a key using HKDF-SHA256.
NSData *deriveE2EEKey(NSData *keyMaterial, NSString *saltString, NSUInteger outputLength);

/// Decrypt AES-256-GCM (ciphertext || 16-byte tag).
NSData *decryptAESGCM(NSData *ciphertextWithTag, NSData *key, NSData *iv, NSData *aad);

/// Load the client RSA private key from preferences.
RSA *getClientPrivKey(void);

#endif /* SKYGLOW_CRYPTOMANAGER_H */