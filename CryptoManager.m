#import "CryptoManager.h"

RSA *getClientPrivKey(void) {
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    if (!prefs) return NULL;

    NSString *keyString = prefs[@"privateKey"];
    if (!keyString || [keyString length] == 0) {
        NSLog(@"[Crypto] No client private key in preferences");
        return NULL;
    }

    BIO *bio = BIO_new_mem_buf((void *)[keyString UTF8String], -1);
    if (!bio) {
        NSLog(@"[Crypto] Failed to create BIO");
        return NULL;
    }

    RSA *key = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!key) {
        NSLog(@"[Crypto] Failed to parse RSA private key");
    }
    return key;
}

NSData *deriveE2EEKey(NSData *keyMaterial, NSString *saltString, NSUInteger outputLength) {
    if (!keyMaterial || !saltString || outputLength == 0) return nil;

    const EVP_MD *digest = EVP_sha256();
    unsigned char *outKey = malloc(outputLength);
    if (!outKey) return nil;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        free(outKey);
        return nil;
    }

    NSData *saltData = [saltString dataUsingEncoding:NSUTF8StringEncoding];
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

NSData *decryptAESGCM(NSData *ciphertextWithTag, NSData *key, NSData *iv, NSData *aad) {
    if (!ciphertextWithTag || !key || !iv) return nil;

    const NSUInteger tagLength = 16;
    if (ciphertextWithTag.length < tagLength) {
        NSLog(@"[Crypto] Ciphertext too short for GCM tag");
        return nil;
    }

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