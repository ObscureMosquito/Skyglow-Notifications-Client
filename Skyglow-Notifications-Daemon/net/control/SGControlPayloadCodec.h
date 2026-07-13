#ifndef SKYGLOW_SG_CONTROL_PAYLOAD_CODEC_H
#define SKYGLOW_SG_CONTROL_PAYLOAD_CODEC_H

#import <Foundation/Foundation.h>
#import "SGControlChannelProtocol.h"

/* Serialization for the control channel's variable-length payloads.
 * SGCBundleIdListPayload: uint16 count, then per entry uint16 len + UTF-8 bytes
 * (not null-terminated). One definition, shared by every channel participant. */

_Static_assert(sizeof(SGCTokenRequestPayload) == sizeof(SGCBundleIdPayload),
               "token and bundle requests must share identifier wire layout");

static inline NSString *SGCBundleIdentifierDecode(const void *payload,
                                                   uint32_t length) {
    if (!payload || length < sizeof(SGCBundleIdPayload)) return nil;
    const SGCBundleIdPayload *bundlePayload =
        (const SGCBundleIdPayload *)payload;
    size_t bundleLength = strnlen(bundlePayload->bundleID,
                                  sizeof(bundlePayload->bundleID));
    NSString *bundleID = [[NSString alloc]
        initWithBytes:bundlePayload->bundleID
               length:bundleLength
             encoding:NSUTF8StringEncoding];
    if (!SG_IsIdentifierStringSafe(bundleID)) {
#if !__has_feature(objc_arc)
        [bundleID release];
#endif
        return nil;
    }
#if !__has_feature(objc_arc)
    return [bundleID autorelease];
#else
    return bundleID;
#endif
}

static inline NSData *SGCBundleIdListEncode(id bundleIDs) {
    NSMutableData *out = [NSMutableData data];
    uint16_t count = 0;
    [out appendBytes:&count length:sizeof(count)];
    NSMutableSet *seen = [NSMutableSet set];
    for (NSString *b in bundleIDs) {
        if (![b isKindOfClass:[NSString class]] || [seen containsObject:b]) continue;
        NSData *utf8 = [b dataUsingEncoding:NSUTF8StringEncoding];
        if (![utf8 length] || [utf8 length] > 0xFFFF) continue;
        if ([out length] + sizeof(uint16_t) + [utf8 length] > SG_CONTROL_MAX_PAYLOAD) break;
        [seen addObject:b];
        uint16_t len = (uint16_t)[utf8 length];
        [out appendBytes:&len length:sizeof(len)];
        [out appendData:utf8];
        count++;
    }
    [out replaceBytesInRange:NSMakeRange(0, sizeof(count)) withBytes:&count];
    return out;
}

static inline NSArray *SGCBundleIdListDecode(const void *payload, uint32_t length) {
    NSMutableArray *out = [NSMutableArray array];
    if (!payload || length < offsetof(SGCBundleIdListPayload, data)) return out;
    const SGCBundleIdListPayload *list = (const SGCBundleIdListPayload *)payload;
    const uint8_t *p = list->data;
    const uint8_t *end = (const uint8_t *)payload + length;
    for (uint16_t i = 0; i < list->count && (end - p) >= 2; i++) {
        uint16_t len;
        memcpy(&len, p, sizeof(len));
        p += 2;
        if ((NSInteger)(end - p) < (NSInteger)len) break;
        NSString *b = [[NSString alloc] initWithBytes:p length:len encoding:NSUTF8StringEncoding];
        if ([b length]) [out addObject:b];
#if !__has_feature(objc_arc)
        [b release];
#endif
        p += len;
    }
    return out;
}

#endif
