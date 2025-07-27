#import "openssl/evp.h"
#import "openssl/kdf.h"

NSData *deriveE2EEKey(NSData *keyMaterial, NSString *saltString, NSUInteger outputLength);
NSData *decryptAESGCM(NSData *ciphertext, NSData *key, NSData *iv, NSData *authTag, NSData *aad);