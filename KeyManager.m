#import "KeyManager.h"
#import "CommonDefinitions.h"


NSData *OpenSSLBase64Decode(NSString *base64String) {
    // Convert NSString to C string
    const char *input = [base64String cStringUsingEncoding:NSASCIIStringEncoding];
    size_t length = strlen(input);

    // Set up a memory buffer to hold the decoded data
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new_mem_buf(input, (int)length);
    bio = BIO_push(b64, bio);

    // Do not use newlines to flush buffer
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    // Decode
    NSMutableData *decodedData = [NSMutableData dataWithLength:length]; // Length is overestimated
    int decodedLength = BIO_read(bio, decodedData.mutableBytes, (int)length);

    [decodedData setLength:decodedLength];

    BIO_free_all(bio);
    return decodedData;
}


NSData *tlsDecrypt(NSData *inputData, NSString *privateKeyPath) {
    FILE *privateKeyFile = fopen(privateKeyPath.UTF8String, "r");
    if (!privateKeyFile) {
        NSLog(@"Failed to open private key file");
        return nil;
    }

    RSA *rsaPrivateKey = PEM_read_RSAPrivateKey(privateKeyFile, NULL, NULL, NULL);
    if (!rsaPrivateKey) {
        NSLog(@"Failed to read private key");
        fclose(privateKeyFile);
        return nil;
    }

    const size_t rsaSize = RSA_size(rsaPrivateKey);
    unsigned char *decryptedBytes = malloc(rsaSize);
    if (!decryptedBytes) {
        RSA_free(rsaPrivateKey);
        fclose(privateKeyFile);
        NSLog(@"Failed to allocate memory for decryption");
        return nil;
    }

    int resultLength = RSA_private_decrypt((int)[inputData length], [inputData bytes], decryptedBytes, rsaPrivateKey, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsaPrivateKey);
    fclose(privateKeyFile);

    if (resultLength == -1) {
        free(decryptedBytes);
        char *errorBuf[120];
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), errorBuf);
        NSLog(@"Decryption Error: %s", errorBuf);
        return nil;
    }

    NSData *decryptedData = [NSData dataWithBytesNoCopy:decryptedBytes length:resultLength freeWhenDone:YES];
    return decryptedData;
}

