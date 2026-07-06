#ifndef SKYGLOW_SG_CRYPTO_ENGINE_H
#define SKYGLOW_SG_CRYPTO_ENGINE_H

#import <Foundation/Foundation.h>
#import <openssl/rsa.h>

/**
 * Derives an End-to-End Encryption key using HKDF-SHA256.
 */
NSData *SG_CryptoDeriveE2EEKey(NSData *keyMaterial, NSString *salt, NSUInteger outputLength);

/**
 * Decrypts a notification payload using AES-256-GCM.
 */
NSData *SG_CryptoDecryptAESGCM(NSData *ciphertextWithTag, NSData *key, NSData *iv, NSData *aad);

/**
 * Retrieves the local RSA private key from the secure profile.
 */
RSA *SG_CryptoGetClientPrivateKey(void);

#endif