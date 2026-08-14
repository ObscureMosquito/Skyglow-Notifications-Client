#ifndef SKYGLOW_SG_CRYPTO_ENGINE_H
#define SKYGLOW_SG_CRYPTO_ENGINE_H

#import <Foundation/Foundation.h>
#import <openssl/rsa.h>
#import <openssl/x509.h>

NSData *SG_CryptoDeriveE2EEKey(NSData *keyMaterial, NSString *salt, NSUInteger outputLength);
NSData *SG_CryptoDecryptAESGCM(NSData *ciphertextWithTag, NSData *key, NSData *iv, NSData *aad);
RSA *SG_CryptoGetClientPrivateKey(void);
X509 *SG_CryptoParseCertificatePEM(const void *pemBytes, size_t length);
EVP_PKEY *SG_CryptoParsePrivateKeyPEM(const void *pemBytes, size_t length);
BOOL SG_CryptoCertificatePEMIsValid(NSString *pem);
BOOL SG_CryptoIdentityPEMIsValid(NSString *pem);
void SG_CryptoZeroBytes(void *bytes, size_t length);
void SG_CryptoWipeData(NSMutableData *data);
void SG_CryptoLogOpenSSLErrors(const char *logTag, const char *diagnosticCode);

#endif
