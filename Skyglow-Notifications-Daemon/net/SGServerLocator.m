#import "SGServerLocator.h"
#import "SGDatabaseManager.h"
#import "SGConfiguration.h"
#import "SGLog.h"
#include <dns_sd.h>
#include <arpa/inet.h>

#define DNS_CACHE_MAX_AGE_SECONDS 3600.0


static BOOL SG_DNSEndpointValid(NSString *ip, NSString *port) {
    if (!ip || !port) return NO;

    struct in_addr a4; struct in6_addr a6;
    const char *ipc = [ip UTF8String];
    if (!ipc) return NO;
    if (inet_pton(AF_INET, ipc, &a4) != 1 && inet_pton(AF_INET6, ipc, &a6) != 1) return NO;

    NSUInteger n = [port length];
    if (n == 0 || n > 5) return NO;
    for (NSUInteger i = 0; i < n; i++) {
        unichar c = [port characterAtIndex:i];
        if (c < '0' || c > '9') return NO;
    }
    int p = [port intValue];
    return (p > 0 && p <= 65535);
}

@implementation SGServerLocator

+ (NSDictionary *)resolveEndpointForServerAddress:(NSString *)serverAddress {
    if (!serverAddress || [serverAddress length] == 0) return nil;
    
    NSString *dnsName = [serverAddress hasPrefix:@"_sgn."] ? serverAddress : [NSString stringWithFormat:@"_sgn.%@", serverAddress];
    
    NSDictionary *cached = [[SGDatabaseManager sharedManager] cachedDNSForDomain:dnsName maxAge:DNS_CACHE_MAX_AGE_SECONDS];
    if (cached) return cached;

    SGLOGI(SGServerLocator, "code=%s name=%s", SGND_DNS_LOOKUP_STARTED, [dnsName UTF8String]);
    NSDictionary *txt = [self performLiveDNSLookup:dnsName];

    if (txt && SG_DNSEndpointValid(txt[@"tcp_addr"], txt[@"tcp_port"])) {
        SGLOGI(SGServerLocator, "code=%s name=%s ip=%s port=%s result=ok", SGND_DNS_LOOKUP_SUCCEEDED,
                    [dnsName UTF8String], [txt[@"tcp_addr"] UTF8String],
                    [txt[@"tcp_port"] UTF8String]);
        [[SGDatabaseManager sharedManager] storeDNSCacheForDomain:dnsName ip:txt[@"tcp_addr"] port:txt[@"tcp_port"]];
        return txt;
    }

    SGLOGW(SGServerLocator, "code=%s name=%s result=failed", SGND_DNS_LOOKUP_FAILED, [dnsName UTF8String]);
    return nil;
}

+ (void)refreshDNSCacheAsynchronouslyForAddress:(NSString *)serverAddress {
    if (!serverAddress || [serverAddress length] == 0) return;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
        @autoreleasepool { [self resolveEndpointForServerAddress:serverAddress]; }
    });
}

static void DNSSD_API query_callback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
                                     DNSServiceErrorType errorCode, const char *fullname, uint16_t rrtype,
                                     uint16_t rrclass, uint16_t rdlen, const void *rdata, uint32_t ttl, void *context) {
    NSMutableDictionary *results = (__bridge NSMutableDictionary *)context;
    
    if (errorCode != kDNSServiceErr_NoError) {
        SGLOGW(SGServerLocator, "code=%s dns_error=%d result=failed", SGND_DNS_CALLBACK_FAILED, errorCode);
    } else if (rdlen > 0) {
        const uint8_t *ptr = (const uint8_t *)rdata;
        const uint8_t *end = ptr + rdlen;
        
        while (ptr < end) {
            uint8_t len = *ptr++;
            if (len == 0 || ptr + len > end) break;
            
            NSString *entry = [[[NSString alloc] initWithBytes:ptr length:len encoding:NSUTF8StringEncoding] autorelease];
            if (entry) {
                NSArray *components = [entry componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                
                for (NSString *comp in components) {
                    NSRange range = [comp rangeOfString:@"="];
                    if (range.location == NSNotFound) continue;
                    NSString *key = [comp substringToIndex:range.location];
                    NSString *val = [comp substringFromIndex:range.location + 1];

                    if (![key isEqualToString:@"tcp_addr"] && ![key isEqualToString:@"tcp_port"]) continue;
                    if ([val length] == 0 || [results objectForKey:key]) continue;
                    [results setObject:val forKey:key];
                    SGLOGD(SGServerLocator, "code=%s key=%s value=%s", SGND_DNS_TXT_PARSED, [key UTF8String], [val UTF8String]);
                }
            }
            ptr += len;
        }
    }
    
}

+ (NSDictionary *)performLiveDNSLookup:(NSString *)dnsName {
    NSMutableDictionary *results = [NSMutableDictionary dictionary];
    DNSServiceRef sdRef = NULL;
    
    if (DNSServiceQueryRecord(&sdRef, 0, 0, [dnsName UTF8String], kDNSServiceType_TXT, kDNSServiceClass_IN, query_callback, results) != kDNSServiceErr_NoError) {
        return nil;
    }

    int dns_fd = DNSServiceRefSockFD(sdRef);
    if (dns_fd < 0 || dns_fd >= FD_SETSIZE) {
        DNSServiceRefDeallocate(sdRef);
        return nil;
    }
    
    NSDate *timeoutDate = [NSDate dateWithTimeIntervalSinceNow:5.0];
    BOOL done = NO;
    
    while (!done && [[NSDate date] compare:timeoutDate] == NSOrderedAscending) {
        fd_set readfds; FD_ZERO(&readfds); FD_SET(dns_fd, &readfds);
        struct timeval tv = {1, 0};
        
        int sel = select(dns_fd + 1, &readfds, NULL, NULL, &tv);
        if (sel > 0 && FD_ISSET(dns_fd, &readfds)) {
            DNSServiceProcessResult(sdRef);
            if (results[@"tcp_addr"] && results[@"tcp_port"]) done = YES;
        } else if (sel < 0 && errno != EINTR) {
            break;
        }
    }
    
    DNSServiceRefDeallocate(sdRef);
    return results.count > 0 ? results : nil;
}

@end
