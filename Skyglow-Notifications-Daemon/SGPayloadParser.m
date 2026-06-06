#import "SGPayloadParser.h"
#import "SGJSONParser.h"
#import <string.h>

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

    /* Binary plist has a fixed magic and never leads with whitespace. */
    if (length >= 8 && memcmp(buffer, "bplist0", 7) == 0) return SGPayloadFormatPlist;

    /* For the text forms, skip insignificant leading whitespace. */
    uint32_t i = 0;
    while (i < length) {
        uint8_t c = buffer[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i++;
        else break;
    }
    if (i >= length) return SGPayloadFormatUnknown;

    uint8_t c = buffer[i];
    if (c == '{' || c == '[') return SGPayloadFormatJSON;  /* JSON object/array  */
    if (c == '<')              return SGPayloadFormatPlist; /* XML plist (<?xml/<plist) */

    /* TLV opens with a known one-byte field type. These (0x01-0x04) cannot
     * collide with '{' (0x7B), '[' (0x5B), '<' (0x3C) or 'b' (0x62). */
    if (c == SG_TLV_TYPE_TITLE || c == SG_TLV_TYPE_BODY ||
        c == SG_TLV_TYPE_SOUND || c == SG_TLV_TYPE_CUSTOM_DATA) {
        return SGPayloadFormatTLV;
    }
    return SGPayloadFormatUnknown;
}

#pragma mark - Canonicalization

/* Recursively rebuilds a parsed graph keeping only property-list-representable
 * values with string keys. Drops NSNull (which JSON can produce but binary
 * plist cannot encode) and anything unexpected, guaranteeing the result
 * survives the NSPropertyListSerialization IPC hop to SpringBoard. Returns nil
 * for a value that should be omitted entirely. */
static id SG_MakePlistSafe(id obj) {
    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *out = [NSMutableDictionary dictionary];
        NSDictionary *in = (NSDictionary *)obj;
        for (id key in in) {
            if (![key isKindOfClass:[NSString class]]) continue; /* plist keys must be strings */
            id safe = SG_MakePlistSafe([in objectForKey:key]);
            if (safe) [out setObject:safe forKey:key];
        }
        return out;
    }
    if ([obj isKindOfClass:[NSArray class]]) {
        NSMutableArray *out = [NSMutableArray array];
        for (id val in (NSArray *)obj) {
            id safe = SG_MakePlistSafe(val);
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
    return nil; /* NSNull and any non-plist type are dropped */
}

/* Promotes the flat TLV dictionary ({title, body, sound, custom_data}) into the
 * canonical APNS userInfo shape so all three encodings converge on one model.
 * Returns nil when there is nothing deliverable. */
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

/* Validates an already-APNS-shaped graph (from JSON or plist). The top level
 * must be a dictionary; if it carries an "aps" entry that entry must itself be
 * a dictionary. Returns a plist-safe copy, or nil. */
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

#pragma mark - Unified decode

NSDictionary *SG_PayloadDecode(const uint8_t *buffer, uint32_t length, uint8_t contentType) {
    if (!buffer || length == 0) return nil;

    /* Cross-check: the declared content_type is the dispatch hint, but the
     * bytes get the final say. A type that names another format outright is a
     * lie we reject before parsing; the strict per-format decoder is the real
     * gate for everything else. */
    SGPayloadFormat sniffed = SG_PayloadSniffFormat(buffer, length);

    switch (contentType) {
        case SGPayloadFormatJSON:
            if (sniffed != SGPayloadFormatJSON) return nil;
            return SG_DecodeJSON(buffer, length);

        case SGPayloadFormatPlist:
            if (sniffed != SGPayloadFormatPlist) return nil;
            return SG_DecodePlist(buffer, length);

        case SGPayloadFormatTLV:
            /* TLV may sniff as TLV or Unknown (its body is opaque past the
             * first field), but never as another structured format. */
            if (sniffed == SGPayloadFormatJSON || sniffed == SGPayloadFormatPlist) return nil;
            return SG_NormalizeTLVToAPNS(SG_PayloadParseBinaryData(buffer, length));

        default:
            return nil; /* unknown / reserved content type */
    }
}
