#import "SNRegisterAccount.h"
#import "../ServerLocationFinder.h"
#include <CFNetwork/CFHost.h>
#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>
#import <dns_sd.h>


// blocking
NSString* RegisterAccount(NSString *server_address) {
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    
    if (!prefs) {
        prefs = [[NSMutableDictionary alloc] init];
    }

    if (!server_address || [server_address length] == 0) {
        return @"Invalid server address provided";
    }
    

    // Generating client SSL certificate
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4); // RSA_F4 is a common public exponent

    if (RSA_generate_key_ex(rsa, 2048, bn, NULL) != 1) {
        // Handle key generation error
        NSLog(@"Failed to generate RSA key");
        RSA_free(rsa);
        BN_free(bn);
        return @"failed to generate client RSA key";
    }

    // Convert private key to string
    BIO *privateKeyBio = BIO_new(BIO_s_mem());
    if (!privateKeyBio || PEM_write_bio_RSAPrivateKey(privateKeyBio, rsa, NULL, NULL, 0, NULL, NULL) != 1) {
        NSLog(@"Failed to convert private key to PEM");
        if (privateKeyBio) BIO_free(privateKeyBio);
        RSA_free(rsa);
        BN_free(bn);
        return @"failed to convert client private RSA key for storage";
    }
    
    // Convert public key to string
    BIO *publicKeyBio = BIO_new(BIO_s_mem());
    if (!publicKeyBio || PEM_write_bio_RSA_PUBKEY(publicKeyBio, rsa) != 1) {
        NSLog(@"Failed to convert public key to PEM");
        BIO_free(privateKeyBio);
        if (publicKeyBio) BIO_free(publicKeyBio);
        RSA_free(rsa);
        BN_free(bn);
        return @"failed to convert client public RSA key for storage";
    }
    
    // Get length of the key data
    long privateKeyLength = BIO_pending(privateKeyBio);
    long publicKeyLength = BIO_pending(publicKeyBio);
    
    // Allocate buffers for the key strings
    char *privateKeyBuffer = malloc(privateKeyLength + 1);
    char *publicKeyBuffer = malloc(publicKeyLength + 1);
    
    if (!privateKeyBuffer || !publicKeyBuffer) {
        NSLog(@"Failed to allocate memory for key buffers");
        BIO_free(privateKeyBio);
        BIO_free(publicKeyBio);
        if (privateKeyBuffer) free(privateKeyBuffer);
        if (publicKeyBuffer) free(publicKeyBuffer);
        RSA_free(rsa);
        BN_free(bn);
        return @"could not allocate memory for keys (OOM?)";
    }
    
    // Read keys into buffers
    BIO_read(privateKeyBio, privateKeyBuffer, privateKeyLength);
    BIO_read(publicKeyBio, publicKeyBuffer, publicKeyLength);
    
    // Null-terminate the strings
    privateKeyBuffer[privateKeyLength] = '\0';
    publicKeyBuffer[publicKeyLength] = '\0';
    
    // Convert to NSString
    NSString *privateKeyString = [NSString stringWithUTF8String:privateKeyBuffer];
    NSString *publicKeyString = [NSString stringWithUTF8String:publicKeyBuffer];
    
    // Save to preferences dictionary
    [prefs setObject:privateKeyString forKey:@"privateKey"];
    [prefs setObject:publicKeyString forKey:@"publicKey"];
    
    // Clean up
    BIO_free(privateKeyBio);
    BIO_free(publicKeyBio);
    free(privateKeyBuffer);
    free(publicKeyBuffer);
    RSA_free(rsa);
    BN_free(bn);
    

    // TXT Record "tcp_addr=tcp.sgntest.preloading.dev tcp_port=7373 http_addr=https://http.sgntest.preloading.dev"
    
    NSDictionary *txtRecords = QueryServerLocation([@"_sgn." stringByAppendingString:server_address]);
    if (txtRecords) {
        NSLog(@"Found TXT records: %@", txtRecords);
        
        // Extract connection details
        NSString *httpAddress = txtRecords[@"http_addr"];

        // Make the body
        NSMutableDictionary *requestData = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                publicKeyString, @"pub_key", 
                                nil];

        NSError *err = nil;
        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:requestData options:0 error:&err];
        if (err) {
            return @"could not encode client request";
        }
        
        NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:[NSURL URLWithString:[NSString stringWithFormat:@"%@/snd/register_device",httpAddress]]];
        [request setHTTPMethod:@"POST"];
        [request setHTTPBody:jsonData];

        NSURLResponse *response = nil;
        NSData *responseData = [NSURLConnection sendSynchronousRequest:request 
                                                returningResponse:&response 
                                                            error:&err];
        if (err) {
            return @"could not send request to server (is server down?)";
        }

        id object = [NSJSONSerialization
                      JSONObjectWithData:responseData
                      options:0
                      error:&err];

        if (err) {
            return @"server returned an invalid responce";
        }

        if(![object isKindOfClass:[NSDictionary class]]) {
            return @"server returned an invalid responce";
        }
        
        NSDictionary *results = object;

        NSString *status = results[@"status"];
        if (![status isEqualToString:@"sucess"]) {
            return @"registration was not sucessful";
        }
        NSString *userAddress = results[@"device_address"];
        NSString *serverPubKeyString = results[@"server_pub_key"];
        [prefs setObject:userAddress forKey:@"device_address"];
        [prefs setObject:serverPubKeyString forKey:@"server_pub_key"];
        [prefs setObject:server_address forKey:@"server_address"];

        [prefs writeToFile:plistPath atomically:YES];
        return nil;
    } else {
        NSLog(@"Failed to retrieve TXT records for %@", server_address);
        return @"could not find server";
    }
}