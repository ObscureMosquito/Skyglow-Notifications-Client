/*
 * SNRegisterAccount.m
 * SkyglowNotificationsDaemon
 */

#import "SNRegisterAccount.h"
#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>

// DNS & Networking Headers
#include <dns_sd.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// OpenSSL Headers
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>

// --- DNS Logic (iOS 6 Compatible) ---

static void QueryRecordCallback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
                                DNSServiceErrorType errorCode, const char *fullname, uint16_t rrtype,
                                uint16_t rrclass, uint16_t rdlen, const void *rdata, uint32_t ttl, void *context) {
    
    if (errorCode != kDNSServiceErr_NoError || rrtype != kDNSServiceType_TXT || !rdata) {
        return;
    }

    NSMutableDictionary *txtRecords = (__bridge NSMutableDictionary *)context;
    uint16_t itemCount = TXTRecordGetCount(rdlen, rdata);

    for (uint16_t i = 0; i < itemCount; i++) {
        char keyBuf[256];
        uint8_t valLen = 0;
        const void *valPtr = NULL;

        if (TXTRecordGetItemAtIndex(rdlen, rdata, i, sizeof(keyBuf), keyBuf, &valLen, &valPtr) == kDNSServiceErr_NoError) {
            NSString *key = [NSString stringWithUTF8String:keyBuf];
            NSString *value = nil;
            if (valPtr && valLen > 0) {
                // Autorelease is important here if not using ARC, but safe either way
                value = [[NSString alloc] initWithBytes:valPtr length:valLen encoding:NSUTF8StringEncoding];
            }
            if (key && value) {
                [txtRecords setObject:value forKey:key];
            }
        }
    }
}

// iOS 6 Compatible Helper
static NSDictionary *NormalizeTXT(NSDictionary *raw) {
    if (!raw) return nil;
    
    NSMutableDictionary *result = [NSMutableDictionary dictionary];

    for (NSString *key in raw) {
        NSString *value = raw[key];

        // iOS 6 fix: Use rangeOfString instead of containsString
        BOOL hasSpace = [value rangeOfString:@" "].location != NSNotFound;
        BOOL hasEquals = [value rangeOfString:@"="].location != NSNotFound;

        if (hasSpace && hasEquals) {
            NSString *combined = [NSString stringWithFormat:@"%@=%@", key, value];
            NSArray *parts = [combined componentsSeparatedByString:@" "];
            
            for (NSString *part in parts) {
                NSRange eq = [part rangeOfString:@"="];
                if (eq.location != NSNotFound) {
                    NSString *k = [part substringToIndex:eq.location];
                    NSString *v = [part substringFromIndex:eq.location + 1];
                    if ([k length] > 0)
                        [result setObject:v forKey:k];
                }
            }
        } else {
            [result setObject:value forKey:key];
        }
    }
    
    return [result count] > 0 ? result : nil;
}

static NSDictionary *QueryTXT(NSString *domain) {
    if (!domain) return nil;
    
    NSMutableDictionary *txtRecords = [NSMutableDictionary dictionary];
    DNSServiceRef serviceRef = NULL;
    
    DNSServiceErrorType err = DNSServiceQueryRecord(&serviceRef, 0, 0, [domain UTF8String],
                                                    kDNSServiceType_TXT, kDNSServiceClass_IN,
                                                    QueryRecordCallback, (__bridge void *)txtRecords);
    
    if (err != kDNSServiceErr_NoError) return nil;
    
    int fd = DNSServiceRefSockFD(serviceRef);
    if (fd < 0) {
        DNSServiceRefDeallocate(serviceRef);
        return nil;
    }
    
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    
    struct timeval timeout = {4, 0}; 
    int result = select(fd + 1, &readfds, NULL, NULL, &timeout);
    
    if (result > 0) {
        DNSServiceProcessResult(serviceRef);
    }
    
    DNSServiceRefDeallocate(serviceRef);
    
    if ([txtRecords count] > 0) {
        return NormalizeTXT(txtRecords);
    }
    return nil;
}

static NSDictionary *ResolveServerLocation(NSString *domain) {
    NSDictionary *res;
    
    // Check specific subdomain first
    res = QueryTXT([NSString stringWithFormat:@"_sgn.sgn.%@", domain]);
    if (res && [res objectForKey:@"tcp_addr"]) return res;
    
    // Check standard tcp subdomain
    res = QueryTXT([NSString stringWithFormat:@"_sgn._tcp.%@", domain]);
    if (res && [res objectForKey:@"tcp_addr"]) return res;
    
    return nil;
}

// --- Main Registration Function ---

NSString* RegisterAccount(NSString *server_address) {
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    
    if (!prefs) {
        prefs = [[NSMutableDictionary alloc] init];
    }

    if (!server_address || [server_address length] == 0) {
        return @"Invalid server address provided";
    }
    
    // RSA Key Gen
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);

    if (RSA_generate_key_ex(rsa, 2048, bn, NULL) != 1) {
        RSA_free(rsa);
        BN_free(bn);
        return @"failed to generate client RSA key";
    }

    BIO *privateKeyBio = BIO_new(BIO_s_mem());
    if (!privateKeyBio || PEM_write_bio_RSAPrivateKey(privateKeyBio, rsa, NULL, NULL, 0, NULL, NULL) != 1) {
        if (privateKeyBio) BIO_free(privateKeyBio);
        RSA_free(rsa);
        BN_free(bn);
        return @"failed to convert client private RSA key";
    }
    
    BIO *publicKeyBio = BIO_new(BIO_s_mem());
    if (!publicKeyBio || PEM_write_bio_RSA_PUBKEY(publicKeyBio, rsa) != 1) {
        BIO_free(privateKeyBio);
        if (publicKeyBio) BIO_free(publicKeyBio);
        RSA_free(rsa);
        BN_free(bn);
        return @"failed to convert client public RSA key";
    }
    
    long privateKeyLength = BIO_pending(privateKeyBio);
    long publicKeyLength = BIO_pending(publicKeyBio);
    
    char *privateKeyBuffer = malloc(privateKeyLength + 1);
    char *publicKeyBuffer = malloc(publicKeyLength + 1);
    
    if (!privateKeyBuffer || !publicKeyBuffer) {
        BIO_free(privateKeyBio);
        BIO_free(publicKeyBio);
        if (privateKeyBuffer) free(privateKeyBuffer);
        if (publicKeyBuffer) free(publicKeyBuffer);
        RSA_free(rsa);
        BN_free(bn);
        return @"could not allocate memory for keys";
    }
    
    BIO_read(privateKeyBio, privateKeyBuffer, privateKeyLength);
    BIO_read(publicKeyBio, publicKeyBuffer, publicKeyLength);
    
    privateKeyBuffer[privateKeyLength] = '\0';
    publicKeyBuffer[publicKeyLength] = '\0';
    
    NSString *privateKeyString = [NSString stringWithUTF8String:privateKeyBuffer];
    NSString *publicKeyString = [NSString stringWithUTF8String:publicKeyBuffer];
    
    [prefs setObject:privateKeyString forKey:@"privateKey"];
    [prefs setObject:publicKeyString forKey:@"publicKey"];
    
    BIO_free(privateKeyBio);
    BIO_free(publicKeyBio);
    free(privateKeyBuffer);
    free(publicKeyBuffer);
    RSA_free(rsa);
    BN_free(bn);
    

    // DNS Resolution
    NSDictionary *txtRecords = ResolveServerLocation(server_address);
    
    if (txtRecords) {
        NSLog(@"[Skyglow] Found TXT records: %@", txtRecords);
        
        NSString *httpAddress = [txtRecords objectForKey:@"http_addr"];
        if (!httpAddress) return @"DNS record found but missing 'http_addr'";

        // HTTP Request
        NSMutableDictionary *requestData = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                            publicKeyString, @"pub_key",
                                            nil];

        NSError *err = nil;
        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:requestData options:0 error:&err];
        if (err) return @"could not encode client request";
        
        NSString *urlString = [NSString stringWithFormat:@"%@/snd/register_device", httpAddress];
        NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:[NSURL URLWithString:urlString]];
        [request setHTTPMethod:@"POST"];
        [request setHTTPBody:jsonData];
        [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

        NSURLResponse *response = nil;
        NSData *responseData = [NSURLConnection sendSynchronousRequest:request
                                                     returningResponse:&response
                                                                 error:&err];
        
        if (err) return @"could not send request to server";

        id object = [NSJSONSerialization JSONObjectWithData:responseData options:0 error:&err];

        if (err || ![object isKindOfClass:[NSDictionary class]]) {
            return @"server returned an invalid response";
        }
        
        NSDictionary *results = object;
        NSString *status = [results objectForKey:@"status"];
        
        if (![status isEqualToString:@"sucess"]) {
             return [NSString stringWithFormat:@"registration failed: %@", status];
        }
        
        NSString *userAddress = [results objectForKey:@"device_address"];
        NSString *serverPubKeyString = [results objectForKey:@"server_pub_key"];
        
        [prefs setObject:userAddress forKey:@"device_address"];
        [prefs setObject:serverPubKeyString forKey:@"server_pub_key"];
        [prefs setObject:server_address forKey:@"server_address"];

        [prefs writeToFile:plistPath atomically:YES];
        return nil;
    } else {
        return @"could not find server (DNS TXT record missing)";
    }
}