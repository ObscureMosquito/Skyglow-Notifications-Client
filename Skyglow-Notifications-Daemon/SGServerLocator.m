#import "SGServerLocator.h"
#import "SGDatabaseManager.h"
#import "SGConfiguration.h"
#include <dns_sd.h>

#define DNS_CACHE_MAX_AGE_SECONDS 3600.0

@implementation SGServerLocator

+ (NSDictionary *)resolveEndpointForServerAddress:(NSString *)serverAddress {
    if (!serverAddress || [serverAddress length] == 0) return nil;
    
    NSString *dnsName = [serverAddress hasPrefix:@"_sgn."] ? serverAddress : [NSString stringWithFormat:@"_sgn.%@", serverAddress];
    
    NSDictionary *cached = [[SGDatabaseManager sharedManager] cachedDNSForDomain:dnsName maxAge:DNS_CACHE_MAX_AGE_SECONDS];
    if (cached) return cached;

    NSLog(@"[SGServerLocator] Performing live DNS-SD lookup for: %@", dnsName);
    NSDictionary *txt = [self performLiveDNSLookup:dnsName];
    
    if (txt && txt[@"tcp_addr"] && txt[@"tcp_port"]) {
        NSLog(@"[SGServerLocator] Live lookup success -> %@:%@", txt[@"tcp_addr"], txt[@"tcp_port"]);
        [[SGDatabaseManager sharedManager] storeDNSCacheForDomain:dnsName ip:txt[@"tcp_addr"] port:txt[@"tcp_port"]];
    } else {
        NSLog(@"[SGServerLocator] Live lookup failed or returned incomplete TXT records.");
    }
    
    return txt;
}

+ (void)refreshDNSCacheAsynchronouslyForAddress:(NSString *)serverAddress {
    if (!serverAddress || [serverAddress length] == 0) return;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
        @autoreleasepool { [self resolveEndpointForServerAddress:serverAddress]; }
    });
}

// ── Internal GCD Async Logic ────────────────────────────────────────

static void DNSSD_API query_callback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
                                     DNSServiceErrorType errorCode, const char *fullname, uint16_t rrtype,
                                     uint16_t rrclass, uint16_t rdlen, const void *rdata, uint32_t ttl, void *context) {
    NSMutableDictionary *results = (__bridge NSMutableDictionary *)context;
    
    if (errorCode != kDNSServiceErr_NoError) {
        NSLog(@"[SGServerLocator] mDNSResponder callback error code: %d", errorCode);
    } else if (rdlen > 0) {
        const uint8_t *ptr = (const uint8_t *)rdata;
        const uint8_t *end = ptr + rdlen;
        
        while (ptr < end) {
            uint8_t len = *ptr++;
            if (len == 0 || ptr + len > end) break;
            
            NSString *entry = [[[NSString alloc] initWithBytes:ptr length:len encoding:NSUTF8StringEncoding] autorelease];
            if (entry) {
                // NEW: Split the entry by spaces to handle flat DNS records
                NSArray *components = [entry componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                
                for (NSString *comp in components) {
                    NSRange range = [comp rangeOfString:@"="];
                    if (range.location != NSNotFound) {
                        NSString *key = [comp substringToIndex:range.location];
                        NSString *val = [comp substringFromIndex:range.location + 1];
                        [results setObject:val forKey:key];
                        NSLog(@"[SGServerLocator] Parsed TXT component: %@ = %@", key, val);
                    }
                }
            }
            ptr += len;
        }
    }
    
}

+ (NSDictionary *)performLiveDNSLookup:(NSString *)dnsName {
    NSMutableDictionary *results = [NSMutableDictionary dictionary];
    DNSServiceRef sdRef = NULL;
    
    // Pass the dictionary directly as the context
    if (DNSServiceQueryRecord(&sdRef, 0, 0, [dnsName UTF8String], kDNSServiceType_TXT, kDNSServiceClass_IN, query_callback, results) != kDNSServiceErr_NoError) {
        return nil;
    }

    int dns_fd = DNSServiceRefSockFD(sdRef);
    NSDate *timeoutDate = [NSDate dateWithTimeIntervalSinceNow:5.0];
    BOOL done = NO;
    
    while (!done && [[NSDate date] compare:timeoutDate] == NSOrderedAscending) {
        fd_set readfds; FD_ZERO(&readfds); FD_SET(dns_fd, &readfds);
        struct timeval tv = {1, 0}; // 1 second intervals
        
        int sel = select(dns_fd + 1, &readfds, NULL, NULL, &tv);
        if (sel > 0 && FD_ISSET(dns_fd, &readfds)) {
            DNSServiceProcessResult(sdRef);
            // If the callback populated results, we are done
            if (results.count > 0) done = YES; 
        } else if (sel < 0 && errno != EINTR) {
            break; // Socket error
        }
    }
    
    DNSServiceRefDeallocate(sdRef);
    return results.count > 0 ? results : nil;
}

@end