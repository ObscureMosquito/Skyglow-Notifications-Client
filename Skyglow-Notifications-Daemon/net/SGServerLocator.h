#ifndef SKYGLOW_SG_SERVER_LOCATOR_H
#define SKYGLOW_SG_SERVER_LOCATOR_H

#import <Foundation/Foundation.h>
#include <stdbool.h>
#include <string.h>

/** Strict decimal TCP port: 1-5 digits, 1-65535. */
static inline bool SG_PortCStringIsValid(const char *s, size_t n) {
    if (!s || n == 0 || n > 5) return false;
    int p = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return false;
        p = p * 10 + (s[i] - '0');
    }
    return p > 0 && p <= 65535;
}

@interface SGServerLocator : NSObject

/** Resolves IP+port via DNS-SD TXT records; results cached for one hour. */
+ (NSDictionary *)resolveEndpointForServerAddress:(NSString *)serverAddress;

+ (void)refreshDNSCacheAsynchronouslyForAddress:(NSString *)serverAddress;

@end

#endif