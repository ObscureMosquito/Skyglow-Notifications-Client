#ifndef SKYGLOW_SG_CRYPTO_ENGINE_H
#define SKYGLOW_SG_CRYPTO_ENGINE_H

#import <Foundation/Foundation.h>
#import <openssl/rsa.h>

NSData *SG_CryptoDeriveE2EEKey(NSData *keyMaterial, NSString *salt, NSUInteger outputLength);
NSData *SG_CryptoDecryptAESGCM(NSData *ciphertextWithTag, NSData *key, NSData *iv, NSData *aad);
RSA *SG_CryptoGetClientPrivateKey(void);

#endif