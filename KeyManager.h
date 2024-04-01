#import <Foundation/Foundation.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

// Functions
NSString *decryptWithPrivateKey(NSString *encryptedDataString);
NSData *OpenSSLBase64Decode(NSString *base64String);
