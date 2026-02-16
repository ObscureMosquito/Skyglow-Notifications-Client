#import "ServerLocationFinder.h"
#include <dns_sd.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// --- Helper: Parse DNS TXT Record Data (iOS 6 Safe) ---

static NSDictionary *NormalizeTXT(NSDictionary *raw) {
    if (!raw) return nil;
    
    NSMutableDictionary *result = [NSMutableDictionary dictionary];

    for (NSString *key in raw) {
        NSString *value = [raw objectForKey:key];

        // Check for concatenated records (e.g. "key1=val1 key2=val2")
        // iOS 6 compatible: rangeOfString instead of containsString
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

// --- Helper: DNS Callback ---

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
                value = [[NSString alloc] initWithBytes:valPtr length:valLen encoding:NSUTF8StringEncoding];
            }
            if (key && value) {
                [txtRecords setObject:value forKey:key];
            }
        }
    }
}

// --- Helper: Low-Level Query ---

static NSDictionary *QueryTXT(NSString *domain) {
    if (!domain) return nil;
    
    NSLog(@"[ServerLocationFinder] Querying TXT for: %@", domain);
    
    NSMutableDictionary *txtRecords = [NSMutableDictionary dictionary];
    DNSServiceRef serviceRef = NULL;
    
    DNSServiceErrorType err = DNSServiceQueryRecord(&serviceRef, 0, 0, [domain UTF8String],
                                                    kDNSServiceType_TXT, kDNSServiceClass_IN,
                                                    QueryRecordCallback, (__bridge void *)txtRecords);
    
    if (err != kDNSServiceErr_NoError) {
        NSLog(@"[ServerLocationFinder] DNSServiceQueryRecord failed: %d", err);
        return nil;
    }
    
    int fd = DNSServiceRefSockFD(serviceRef);
    if (fd < 0) {
        DNSServiceRefDeallocate(serviceRef);
        return nil;
    }
    
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    
    // 5 Second Timeout is usually enough for local/cached DNS
    struct timeval timeout = {5, 0}; 
    int result = select(fd + 1, &readfds, NULL, NULL, &timeout);
    
    if (result > 0) {
        DNSServiceProcessResult(serviceRef);
    } else {
        NSLog(@"[ServerLocationFinder] Timeout or Error waiting for: %@", domain);
    }
    
    DNSServiceRefDeallocate(serviceRef);
    
    if ([txtRecords count] > 0) {
        return NormalizeTXT(txtRecords);
    }
    return nil;
}

// --- Helper: Smart Resolution Logic ---

static NSDictionary *ResolveSmart(NSString *baseDomain) {
    NSDictionary *res;
    
    // 1. Try _sgn.sgn.<domain> (The most standard one for this setup)
    res = QueryTXT([NSString stringWithFormat:@"_sgn.sgn.%@", baseDomain]);
    if (res) return res;
    
    // 2. Try _sgn._tcp.<domain>
    res = QueryTXT([NSString stringWithFormat:@"_sgn._tcp.%@", baseDomain]);
    if (res) return res;

    // 3. Try _sgn.<domain> (Legacy/Fallback)
    res = QueryTXT([NSString stringWithFormat:@"_sgn.%@", baseDomain]);
    if (res) return res;
    
    return nil;
}

// --- Main Public API ---

NSDictionary *QueryServerLocation(NSString *domainInput) {
    if (!domainInput || [domainInput length] == 0) return nil;

    NSString *cleanDomain = domainInput;

    // The daemon seems to be passing "_sgn.skyglow.es" based on your logs.
    // We need to strip that prefix so we can try the correct variations like "_sgn.sgn..."
    if ([domainInput hasPrefix:@"_sgn."]) {
        cleanDomain = [domainInput substringFromIndex:5]; // Remove "_sgn."
        NSLog(@"[ServerLocationFinder] Detected prefix. Stripped to: %@", cleanDomain);
    }
    
    // Now run the smart resolution on the clean domain (e.g., "skyglow.es")
    return ResolveSmart(cleanDomain);
}