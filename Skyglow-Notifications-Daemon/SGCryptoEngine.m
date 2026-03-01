#import "SGCryptoEngine.h"
#import "SGConfiguration.h"
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

RSA *SG_CryptoGetClientPrivateKey(void) {
    NSString *keyString = [[SGConfiguration sharedConfiguration] privateKeyPEM];
    if (!keyString || keyString.length == 0) return NULL;

    const char *utf8Key = [keyString UTF8String];
    BIO *bio = BIO_new_mem_buf((void *)utf8Key, (int)strlen(utf8Key));
    if (!bio) return NULL;

    RSA *key = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    if (!key) {
        NSLog(@"[SGCryptoEngine] OpenSSL Failed to read PEM RSA Private Key!");
        unsigned long openSslErr;
        while ((openSslErr = ERR_get_error()) != 0) {
            char errBuf[256];
            ERR_error_string_n(openSslErr, errBuf, sizeof(errBuf));
            NSLog(@"[SGCryptoEngine] OpenSSL Error: %s", errBuf);
        }
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