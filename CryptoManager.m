#import "CryptoManager.h"

NSData *deriveE2EEKey(NSData *keyMaterial, NSString *saltString, NSUInteger outputLength) {
    const EVP_MD *digest = EVP_sha256();
    unsigned char *outKey = malloc(outputLength);
    if (!outKey) return nil;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        free(outKey);
        return nil;
    }

    NSData *saltData = [saltString dataUsingEncoding:NSUTF8StringEncoding];

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, digest) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, saltData.bytes, (int)saltData.length) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, keyMaterial.bytes, (int)keyMaterial.length) <= 0 ||
        EVP_PKEY_derive(pctx, outKey, &(size_t){outputLength}) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        free(outKey);
        return nil;
    }

    NSData *result = [NSData dataWithBytes:outKey length:outputLength];
    EVP_PKEY_CTX_free(pctx);
    free(outKey);
    return result;
}