#import "SGPayloadParser.h"
#import "SGJSONParser.h"
#import "SGStructuredTLV.h"
#import <string.h>
#import <zlib.h>

NSDictionary *SG_PayloadParseBinaryData(const uint8_t *buffer, uint32_t length) {
    if (!buffer || length == 0) return @{};

    NSMutableDictionary *parsedData = [NSMutableDictionary dictionary];
    uint32_t offset = 0;

    while (offset < length) {
        if ((uint64_t)offset + 3 > length) return nil;

        uint8_t type = buffer[offset];
        uint16_t valLen = (buffer[offset + 1] << 8) | buffer[offset + 2];
        offset += 3;

        if ((uint64_t)offset + valLen > length) return nil;

        if (valLen > 0) {
            if (type == SG_TLV_TYPE_TITLE || type == SG_TLV_TYPE_BODY || type == SG_TLV_TYPE_SOUND) {
                NSString *str = [[NSString alloc] initWithBytes:&buffer[offset]
                                                         length:valLen
                                                       encoding:NSUTF8StringEncoding];
                if (str) {
                    NSString *key = (type == SG_TLV_TYPE_TITLE) ? @"title" : 
                                    (type == SG_TLV_TYPE_BODY) ? @"body" : @"sound";
                    [parsedData setObject:str forKey:key];
                    [str release];
                }
            } else if (type == SG_TLV_TYPE_CUSTOM_DATA) {
                NSData *data = [NSData dataWithBytes:&buffer[offset] length:valLen];
                [parsedData setObject:data forKey:@"custom_data"];
            }
        }
        offset += valLen;
    }

    return parsedData;
}

#pragma mark - Format sniffing

SGPayloadFormat SG_PayloadSniffFormat(const uint8_t *buffer, uint32_t length) {
    if (!buffer || length == 0) return SGPayloadFormatUnknown;

    if (length >= 8 && memcmp(buffer, "bplist0", 7) == 0) return SGPayloadFormatPlist;

    const uint8_t *cursor = SG_JSONSkipWhitespace(buffer, buffer + length);
    if (cursor >= buffer + length) return SGPayloadFormatUnknown;

    uint8_t c = *cursor;
    if (c == '{' || c == '[') return SGPayloadFormatJSON;
    if (c == '<')              return SGPayloadFormatPlist;

    if (c == SG_TLV_TYPE_TITLE || c == SG_TLV_TYPE_BODY ||
        c == SG_TLV_TYPE_SOUND || c == SG_TLV_TYPE_CUSTOM_DATA) {
        return SGPayloadFormatTLV;
    }
    return SGPayloadFormatUnknown;
}

#pragma mark - Canonicalization

#define SG_PLIST_MAX_DEPTH 32

static id SG_MakePlistSafeDepth(id obj, int depth, BOOL *tooDeep) {
    if ([obj isKindOfClass:[NSDictionary class]]) {
        if (depth > SG_PLIST_MAX_DEPTH) { *tooDeep = YES; return nil; }
        NSMutableDictionary *out = [NSMutableDictionary dictionary];
        NSDictionary *in = (NSDictionary *)obj;
        for (id key in in) {
            if (![key isKindOfClass:[NSString class]]) continue;
            id safe = SG_MakePlistSafeDepth([in objectForKey:key], depth + 1, tooDeep);
            if (*tooDeep) return nil;
            if (safe) [out setObject:safe forKey:key];
        }
        return out;
    }
    if ([obj isKindOfClass:[NSArray class]]) {
        if (depth > SG_PLIST_MAX_DEPTH) { *tooDeep = YES; return nil; }
        NSMutableArray *out = [NSMutableArray array];
        for (id val in (NSArray *)obj) {
            id safe = SG_MakePlistSafeDepth(val, depth + 1, tooDeep);
            if (*tooDeep) return nil;
            if (safe) [out addObject:safe];
        }
        return out;
    }
    if ([obj isKindOfClass:[NSString class]] ||
        [obj isKindOfClass:[NSNumber class]] ||
        [obj isKindOfClass:[NSData class]]   ||
        [obj isKindOfClass:[NSDate class]]) {
        return obj;
    }
    return nil;
}

static id SG_MakePlistSafe(id obj) {
    BOOL tooDeep = NO;
    return SG_MakePlistSafeDepth(obj, 1, &tooDeep);
}

static NSDictionary *SG_NormalizeTLVToAPNS(NSDictionary *flat) {
    if (!flat || flat.count == 0) return nil;

    NSMutableDictionary *alert = [NSMutableDictionary dictionary];
    if (flat[@"title"]) [alert setObject:flat[@"title"] forKey:@"title"];
    if (flat[@"body"])  [alert setObject:flat[@"body"]  forKey:@"body"];

    NSMutableDictionary *aps = [NSMutableDictionary dictionary];
    if (alert.count > 0)  [aps setObject:alert         forKey:@"alert"];
    if (flat[@"sound"])   [aps setObject:flat[@"sound"] forKey:@"sound"];

    if (aps.count == 0 && !flat[@"custom_data"]) return nil; /* empty/meaningless */

    NSMutableDictionary *result = [NSMutableDictionary dictionaryWithObject:aps forKey:@"aps"];
    if (flat[@"custom_data"]) [result setObject:flat[@"custom_data"] forKey:@"custom_data"];
    return result;
}

static NSDictionary *SG_CanonicalizeAPNSDict(id obj) {
    if (![obj isKindOfClass:[NSDictionary class]]) return nil;
    id aps = [(NSDictionary *)obj objectForKey:@"aps"];
    if (aps && ![aps isKindOfClass:[NSDictionary class]]) return nil;
    NSDictionary *safe = SG_MakePlistSafe(obj);
    if (!safe || safe.count == 0) return nil;
    return safe;
}

static NSDictionary *SG_DecodePlist(const uint8_t *buffer, uint32_t length) {
    NSData *data = [NSData dataWithBytes:buffer length:length];
    id obj = [NSPropertyListSerialization propertyListWithData:data
                                                       options:NSPropertyListImmutable
                                                        format:NULL
                                                         error:NULL];
    return SG_CanonicalizeAPNSDict(obj);
}

static NSDictionary *SG_DecodeJSON(const uint8_t *buffer, uint32_t length) {
    id obj = SG_JSONParse(buffer, length);
    return SG_CanonicalizeAPNSDict(obj);
}

#pragma mark - Decompression

NSData *SG_PayloadInflate(const uint8_t *buffer, uint32_t length, uint32_t maxOut) {
    if (!buffer || length == 0) return nil;

    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    if (inflateInit2(&strm, -15) != Z_OK) return nil;

    strm.next_in  = (Bytef *)buffer;
    strm.avail_in = length;

    NSMutableData *out = [NSMutableData data];
    uint8_t chunk[4096];
    int ret;
    do {
        strm.next_out  = chunk;
        strm.avail_out = sizeof(chunk);
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) { inflateEnd(&strm); return nil; }

        size_t produced = sizeof(chunk) - strm.avail_out;
        if ((uint64_t)out.length + produced > (uint64_t)maxOut) { /* bomb guard */
            inflateEnd(&strm);
            return nil;
        }
        if (produced > 0) [out appendBytes:chunk length:produced];
    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);
    return out.length > 0 ? out : nil;
}

#pragma mark - Unified decode

NSDictionary *SG_PayloadDecode(const uint8_t *buffer, uint32_t length, uint8_t contentType) {
    if (!buffer || length == 0) return nil;

    SGPayloadFormat sniffed = SG_PayloadSniffFormat(buffer, length);

    switch (contentType) {
        case SGPayloadFormatJSON:
            if (sniffed != SGPayloadFormatJSON) return nil;
            return SG_DecodeJSON(buffer, length);

        case SGPayloadFormatPlist:
            if (sniffed != SGPayloadFormatPlist) return nil;
            return SG_DecodePlist(buffer, length);

        case SGPayloadFormatTLV:
            if (sniffed == SGPayloadFormatJSON || sniffed == SGPayloadFormatPlist) return nil;
            return SG_NormalizeTLVToAPNS(SG_PayloadParseBinaryData(buffer, length));

        case SGPayloadFormatTLVStruct:
            if (sniffed == SGPayloadFormatJSON || sniffed == SGPayloadFormatPlist) return nil;
            return SG_CanonicalizeAPNSDict(SG_STLVDecode(buffer, length));

        default:
            return nil;
    }
}
