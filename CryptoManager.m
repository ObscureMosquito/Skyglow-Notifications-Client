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

NSData *decryptAESGCM(NSData *ciphertextWithTag, NSData *key, NSData *iv, NSData *aad) {
    // AES-GCM tag is always 16 bytes
    const NSUInteger tagLength = 16;
    if (ciphertextWithTag.length < tagLength) {
        NSLog(@"Decrypt: ciphertext too short");
        return nil;
    }

    // Split ciphertext and tag
    NSData *ciphertext = [ciphertextWithTag subdataWithRange:NSMakeRange(0, ciphertextWithTag.length - tagLength)];
    NSData *authTag   = [ciphertextWithTag subdataWithRange:NSMakeRange(ciphertextWithTag.length - tagLength, tagLength)];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return nil;

    int len;
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

    if (EVP_DecryptUpdate(ctx, plaintext.mutableBytes, &len, ciphertext.bytes, (int)ciphertext.length) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return nil;
    }
    plaintextLen = len;

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