#import "SNRegisterAccount.h"
#include <CFNetwork/CFHost.h>
#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>
#import <dns_sd.h>

// Functions to query TXT records for our data we need. totally not written by chatgpt since this is annoyingly complex
static void QueryRecordCallback(DNSServiceRef sdRef, DNSServiceFlags flags,
                               uint32_t interfaceIndex, DNSServiceErrorType errorCode,
                               const char *fullname, uint16_t rrtype, uint16_t rrclass,
                               uint16_t rdlen, const void *rdata, uint32_t ttl, void *context) {
    if (errorCode != kDNSServiceErr_NoError) {
        NSLog(@"DNS query failed with error code %d", errorCode);
        return;
    }
    
    NSMutableDictionary *txtRecords = (__bridge NSMutableDictionary *)context;
    
    // Parse the TXT record data
    if (rrtype == kDNSServiceType_TXT && rdata && rdlen > 0) {
        uint16_t txtCount = TXTRecordGetCount(rdlen, rdata);
        
        for (uint16_t i = 0; i < txtCount; i++) {
            char key[256];
            uint8_t valueLen = 0;
            const void *valuePtr = NULL;
            
            DNSServiceErrorType err = TXTRecordGetItemAtIndex(rdlen, rdata, i, 
                                                             sizeof(key), key, 
                                                             &valueLen, &valuePtr);
            
            if (err == kDNSServiceErr_NoError && valuePtr && valueLen > 0) {
                // Convert key and value to NSString
                NSString *keyString = [NSString stringWithUTF8String:key];
                NSString *valueString = [[NSString alloc] initWithBytes:valuePtr 
                                                                length:valueLen 
                                                              encoding:NSUTF8StringEncoding];
                
                if (keyString && valueString) {
                    // Parse for embedded key-value pairs
                    if ([valueString rangeOfString:@"="].location != NSNotFound) {
                        // Split string by spaces
                        NSArray *components = [valueString componentsSeparatedByString:@" "];
                        
                        // The first component without an '=' is the actual value for this key
                        if (components.count > 0 && [components[0] rangeOfString:@"="].location == NSNotFound) {
                            [txtRecords setObject:components[0] forKey:keyString];
                            NSLog(@"Found TXT record: %@ = %@", keyString, components[0]);
                        }
                        
                        // Process remaining components that contain '='
                        for (NSString *part in components) {
                            NSRange range = [part rangeOfString:@"="];
                            if (range.location != NSNotFound) {
                                NSString *embeddedKey = [part substringToIndex:range.location];
                                NSString *embeddedValue = [part substringFromIndex:range.location + 1];
                                
                                if (embeddedKey.length > 0 && embeddedValue.length > 0) {
                                    [txtRecords setObject:embeddedValue forKey:embeddedKey];
                                    NSLog(@"Found embedded TXT record: %@ = %@", embeddedKey, embeddedValue);
                                }
                            }
                        }
                    } else {
                        // Normal key-value pair
                        [txtRecords setObject:valueString forKey:keyString];
                        NSLog(@"Found TXT record: %@ = %@", keyString, valueString);
                    }
                }
            }
        }
    }
}

NSDictionary *QueryTXTRecords(NSString *domain) {
    NSMutableDictionary *txtRecords = [NSMutableDictionary dictionary];
    
    // Validate domain
    if (!domain || [domain length] == 0) {
        NSLog(@"Invalid domain provided");
        return nil;
    }
    
    NSLog(@"Starting direct DNS-SD query for TXT records on domain: %@", domain);
    
    // Use DNSServiceQueryRecord directly without CFHost resolution first
    DNSServiceRef serviceRef;
    DNSServiceErrorType err = DNSServiceQueryRecord(
        &serviceRef,
        0,                   // flags
        0,                   // interface index (any)
        [domain UTF8String], // domain name
        kDNSServiceType_TXT, // query type
        kDNSServiceClass_IN, // query class
        QueryRecordCallback, // callback
        (__bridge void *)(txtRecords) // context
    );
    
    if (err != kDNSServiceErr_NoError) {
        NSLog(@"DNSServiceQueryRecord failed with error code %d for domain: %@", err, domain);
        return nil;
    }
    
    // Create socket from service ref
    int fd = DNSServiceRefSockFD(serviceRef);
    if (fd == -1) {
        NSLog(@"Failed to get socket FD from DNSServiceRef");
        DNSServiceRefDeallocate(serviceRef);
        return nil;
    }
    
    // Set up for select()
    fd_set readfds;
    struct timeval tv;
    tv.tv_sec = 10;  // 10 seconds timeout - increased from 5
    tv.tv_usec = 0;
    
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    
    // Wait for response
    NSLog(@"Waiting for TXT record response...");
    int result = select(fd + 1, &readfds, NULL, NULL, &tv);
    
    if (result > 0) {
        NSLog(@"Got response, processing DNS-SD result");
        DNSServiceProcessResult(serviceRef);
        // The callback will populate txtRecords
    } else if (result == 0) {
        NSLog(@"Timeout waiting for TXT records for domain: %@", domain);
    } else {
        NSLog(@"Error (%d) while waiting for TXT records: %s", errno, strerror(errno));
    }
    
    // Clean up
    DNSServiceRefDeallocate(serviceRef);
    
    // Check if we got any TXT records
    if ([txtRecords count] == 0) {
    NSLog(@"No TXT records found for domain: %@", domain);
    
    // iOS-compatible fallback to verify the domain exists
    NSLog(@"Attempting fallback method to verify domain exists...");
    
    // Use simple hostname lookup as fallback
    CFHostRef host = CFHostCreateWithName(kCFAllocatorDefault, (__bridge CFStringRef)domain);
    if (host) {
        CFStreamError streamError;
        Boolean result = CFHostStartInfoResolution(host, kCFHostAddresses, &streamError);
        
        if (result) {
            NSLog(@"Domain lookup succeeded for %@, but no TXT records were found", domain);
        } else {
            NSLog(@"Domain lookup failed for %@ with error domain %ld, error %d", 
                  domain, streamError.domain, (int)streamError.error);
        }
        
        CFRelease(host);
    }
} else {
    NSLog(@"Successfully retrieved %lu TXT records for domain: %@", 
          (unsigned long)[txtRecords count], domain);
}

return txtRecords;
}
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
    
    NSDictionary *txtRecords = QueryTXTRecords([@"_sgn." stringByAppendingString:server_address]);
    if (txtRecords) {
        NSLog(@"Found TXT records: %@", txtRecords);
        
        // Extract connection details
        NSString *httpAddress = txtRecords[@"http_addr"];

        // Make the body
        NSMutableDictionary *requestData = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                publicKeyString, @"pubKey", 
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