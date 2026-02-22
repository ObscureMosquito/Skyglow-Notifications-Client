#import "ServerLocationFinder.h"
#import "Globals.h"
#include <dns_sd.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DNS_CACHE_MAX_AGE_SECONDS 3600.0

@implementation ServerLocationFinder

+ (NSDictionary *)normalizeTXT:(NSDictionary *)raw {
    if (!raw) return nil;
    NSMutableDictionary *result = [NSMutableDictionary dictionary];

    for (NSString *key in raw) {
        NSString *value = [raw objectForKey:key];
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
                    if ([k length] > 0) [result setObject:v forKey:k];
                }
            }
        } else {
            [result setObject:value forKey:key];
        }
    }
    return [result count] > 0 ? result : nil;
}

// --- Block-based DNS Callback ---
typedef void (^DNSCallbackBlock)(NSDictionary *records, BOOL isDone);

static void QueryRecordCallback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
                                DNSServiceErrorType errorCode, const char *fullname, uint16_t rrtype,
                                uint16_t rrclass, uint16_t rdlen, const void *rdata, uint32_t ttl, void *context) {
    
    DNSCallbackBlock callback = (__bridge DNSCallbackBlock)context;
    NSMutableDictionary *parsedRecords = [NSMutableDictionary dictionary];
    BOOL isDone = ((flags & kDNSServiceFlagsMoreComing) == 0);

    if (errorCode == kDNSServiceErr_NoError && rrtype == kDNSServiceType_TXT && rdata) {
        uint16_t itemCount = TXTRecordGetCount(rdlen, rdata);
        for (uint16_t i = 0; i < itemCount; i++) {
            char keyBuf[256];
            uint8_t valLen = 0;
            const void *valPtr = NULL;

            if (TXTRecordGetItemAtIndex(rdlen, rdata, i, sizeof(keyBuf), keyBuf, &valLen, &valPtr) == kDNSServiceErr_NoError) {
                NSString *key = [NSString stringWithUTF8String:keyBuf];
                NSString *value = valPtr && valLen > 0 ? [[NSString alloc] initWithBytes:valPtr length:valLen encoding:NSUTF8StringEncoding] : nil;
                if (key && value) {
                    [parsedRecords setObject:value forKey:key];
                }
                [value release];
            }
        }
    }

    if (callback) {
        callback(parsedRecords, isDone);
    }
}

+ (NSDictionary *)queryTXT:(NSString *)domain {
    if (!domain) return nil;
    NSLog(@"[ServerLocationFinder] Querying TXT for: %@", domain);
    
    __block NSMutableDictionary *txtRecords = [NSMutableDictionary dictionary];
    __block BOOL queryIsDone = NO;
    
    DNSCallbackBlock blockContext = ^(NSDictionary *records, BOOL isDone) {
        [txtRecords addEntriesFromDictionary:records];
        queryIsDone = isDone;
    };
    
    DNSServiceRef serviceRef = NULL;
    DNSServiceErrorType err = DNSServiceQueryRecord(&serviceRef, 0, 0, [domain UTF8String],
                                                    kDNSServiceType_TXT, kDNSServiceClass_IN,
                                                    QueryRecordCallback, (__bridge void *)blockContext);
    
    if (err != kDNSServiceErr_NoError) {
        NSLog(@"[ServerLocationFinder] DNSServiceQueryRecord failed: %d", err);
        return nil;
    }
    
    int fd = DNSServiceRefSockFD(serviceRef);
    if (fd < 0) {
        DNSServiceRefDeallocate(serviceRef);
        return nil;
    }
    
    NSTimeInterval start = [[NSDate date] timeIntervalSince1970];
    
    while (!queryIsDone && ([[NSDate date] timeIntervalSince1970] - start < 5.0)) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        
        struct timeval tv = {0, 500000}; // 0.5s chunks
        int result = select(fd + 1, &readfds, NULL, NULL, &tv);
        
        if (result > 0) {
            DNSServiceProcessResult(serviceRef);
        } else if (result < 0 && errno != EINTR) {
            NSLog(@"[ServerLocationFinder] select() error: %s", strerror(errno));
            break;
        }
    }
    
    DNSServiceRefDeallocate(serviceRef);
    
    if (!queryIsDone) {
        NSLog(@"[ServerLocationFinder] Timeout waiting for DNS: %@", domain);
    }
    
    if ([txtRecords count] > 0) {
        return [self normalizeTXT:txtRecords];
    }
    return nil;
}

+ (NSDictionary *)resolveServerLocation:(NSString *)serverAddr {
    if (!serverAddr || [serverAddr length] == 0) return nil;
    
    NSString *cleanDomain = serverAddr;
    if ([serverAddr hasPrefix:@"_sgn."]) {
        cleanDomain = [serverAddr substringFromIndex:5];
    }

    NSString *dnsName = [NSString stringWithFormat:@"_sgn.%@", cleanDomain];

    NSDictionary *cached = [db cachedDNSForDomain:dnsName maxAgeSeconds:DNS_CACHE_MAX_AGE_SECONDS];
    if (cached) {
        NSLog(@"[ServerLocationFinder] Using cached DNS for %@", dnsName);
        return cached;
    }

    NSLog(@"[ServerLocationFinder] Cache miss — live DNS lookup for %@", dnsName);
    NSDictionary *txt = [self queryTXT:dnsName];
    if (!txt) return nil;

    NSString *ip   = txt[@"tcp_addr"];
    NSString *port = txt[@"tcp_port"];
    if (ip && port) {
        [db storeDNSCache:dnsName ip:ip port:port];
        NSLog(@"[ServerLocationFinder] Cached DNS: %@ -> %@:%@", dnsName, ip, port);
    }
    return txt;
}

+ (void)refreshDNSCacheAsync:(NSString *)serverAddr {
    if (!serverAddr || [serverAddr length] == 0) return;
    
    NSString *cleanDomain = serverAddr;
    if ([serverAddr hasPrefix:@"_sgn."]) {
        cleanDomain = [serverAddr substringFromIndex:5];
    }
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
        @autoreleasepool {
            NSString *dnsName = [NSString stringWithFormat:@"_sgn.%@", cleanDomain];
            NSDictionary *txt = [self queryTXT:dnsName];
            if (txt) {
                NSString *ip   = txt[@"tcp_addr"];
                NSString *port = txt[@"tcp_port"];
                if (ip && port) {
                    [db storeDNSCache:dnsName ip:ip port:port];
                    NSLog(@"[ServerLocationFinder] DNS cache refreshed: %@:%@", ip, port);
                }
            }
        }
    });
}

@end