#import "SGCryptoEngine.h"
#import "SGConfiguration.h"
#import "SGControlChannelProtocol.h"
#import "SGLog.h"
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

void SG_CryptoLogOpenSSLErrors(const char *logTag, const char *diagnosticCode) {
    unsigned long opensslError;
    while ((opensslError = ERR_get_error()) != 0) {
        char errBuf[256];
        ERR_error_string_n(opensslError, errBuf, sizeof(errBuf));
        SGLog_Write(SGLogLevelError, logTag, "code=%s reason=%s",
                    diagnosticCode, errBuf);
    }
}

X509 *SG_CryptoParseCertificatePEM(const void *pemBytes, size_t length) {
    if (!pemBytes || length == 0 || length > INT_MAX) return NULL;
    BIO *bio = BIO_new_mem_buf((void *)pemBytes, (int)length);
    if (!bio) return NULL;
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return cert;
}

EVP_PKEY *SG_CryptoParsePrivateKeyPEM(const void *pemBytes, size_t length) {
    if (!pemBytes || length == 0 || length > INT_MAX) return NULL;
    BIO *bio = BIO_new_mem_buf((void *)pemBytes, (int)length);
    if (!bio) return NULL;
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return key;
}

BOOL SG_CryptoCertificatePEMIsValid(NSString *pem) {
    if (!SG_LooksLikePEMCertificate(pem)) return NO;
    X509 *cert = SG_CryptoParseCertificatePEM(
        [pem UTF8String], [pem lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
    if (!cert) return NO;
    X509_free(cert);
    return YES;
}

BOOL SG_CryptoIdentityPEMIsValid(NSString *pem) {
    if (!SG_CryptoCertificatePEMIsValid(pem)) return NO;
    EVP_PKEY *key = SG_CryptoParsePrivateKeyPEM(
        [pem UTF8String], [pem lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
    if (!key) return NO;
    EVP_PKEY_free(key);
    return YES;
}

void SG_CryptoZeroBytes(void *bytes, size_t length) {
    if (!bytes) return;
    volatile unsigned char *p = (volatile unsigned char *)bytes;
    while (length--) *p++ = 0;
}

void SG_CryptoWipeData(NSMutableData *data) {
    if (!data) return;
    [data resetBytesInRange:NSMakeRange(0, [data length])];
}

RSA *SG_CryptoGetClientPrivateKey(void) {
    NSData *keyData = [[SGConfiguration sharedConfiguration] privateKeyPEM];
    if (!keyData || keyData.length == 0) return NULL;

    BIO *bio = BIO_new_mem_buf((void *)keyData.bytes, (int)keyData.length);
    if (!bio) return NULL;

    RSA *key = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    if (!key) {
        SGLOGE(SGCryptoEngine, "code=%s result=failed reason=pem_read_private_key", SGND_CRYPTO_PRIVATE_KEY_READ_FAILED);
        SG_CryptoLogOpenSSLErrors("SGCryptoEngine", SGND_CRYPTO_OPENSSL_ERROR);
    }

    BIO_free(bio);
    return key;
}

NSData *SG_CryptoDeriveE2EEKey(NSData *keyMaterial, NSString *salt, NSUInteger outputLength) {
    if (!keyMaterial || !salt || outputLength == 0) return nil;

    const EVP_MD *digest = EVP_sha256();
    unsigned char *outKey = malloc(outputLength);
    if (!outKey) return nil;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        free(outKey);
        return nil;
    }

    NSData *saltData = [salt dataUsingEncoding:NSUTF8StringEncoding];
    size_t outLen = outputLength;

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, digest) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, saltData.bytes, (int)saltData.length) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, keyMaterial.bytes, (int)keyMaterial.length) <= 0 ||
        EVP_PKEY_derive(pctx, outKey, &outLen) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        free(outKey);
        return nil;
    }

    NSData *result = [NSData dataWithBytes:outKey length:outLen];
    EVP_PKEY_CTX_free(pctx);
    free(outKey);
    return result;
}

NSData *SG_CryptoDecryptAESGCM(NSData *ciphertextWithTag, NSData *key, NSData *iv, NSData *aad) {
    if (!ciphertextWithTag || !key || !iv) return nil;
    if (key.length != 32) return nil;

    const NSUInteger tagLength = 16;
    if (ciphertextWithTag.length < tagLength) return nil;

    NSUInteger ctLen = ciphertextWithTag.length - tagLength;
    NSData *ciphertext = [ciphertextWithTag subdataWithRange:NSMakeRange(0, ctLen)];
    NSData *authTag    = [ciphertextWithTag subdataWithRange:NSMakeRange(ctLen, tagLength)];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return nil;

    int len = 0;
    int plaintextLen = 0;
    NSMutableData *plaintext = [NSMutableData dataWithLength:ciphertext.length];

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.length, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key.bytes, iv.bytes) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return nil;
    }

    if (aad && aad.length > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad.bytes, (int)aad.length) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return nil;
        }
    }

    if (ciphertext.length > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext.mutableBytes, &len, ciphertext.bytes, (int)ciphertext.length) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return nil;
        }
        plaintextLen = len;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)authTag.length, (void *)authTag.bytes) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return nil;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext.mutableBytes + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return nil;
    }
    plaintextLen += len;

    EVP_CIPHER_CTX_free(ctx);
    [plaintext setLength:plaintextLen];
    return plaintext;
}
