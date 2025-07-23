#import "openssl/evp.h"
#import "openssl/kdf.h"

NSData *deriveE2EEKey(NSData *keyMaterial, NSString *saltString, NSUInteger outputLength);