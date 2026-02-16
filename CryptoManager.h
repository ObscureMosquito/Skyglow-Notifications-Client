#import <Foundation/Foundation.h>
#import "openssl/evp.h"
#import "openssl/kdf.h"
#include <openssl/pem.h>
#include <openssl/err.h>

NSData *deriveE2EEKey(NSData *keyMaterial, NSString *saltString, NSUInteger outputLength);
NSData *decryptAESGCM(NSData *ciphertextWithTag, NSData *key, NSData *iv, NSData *aad);
RSA* getClientPrivKey();