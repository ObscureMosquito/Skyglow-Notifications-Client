#import "SGStructuredTLV.h"
#import <CoreFoundation/CoreFoundation.h>
#import <string.h>
#import <math.h>

#pragma mark - Decode

/*
 * Single cursor over the byte range. Containers are decoded by temporarily
 * pulling `end` in to the container's payload boundary, parsing children until
 * the cursor reaches it, then restoring `end`. `depth` bounds recursion
 * independently of input size.
 */
typedef struct {
    const uint8_t *p;
    const uint8_t *end;
    int depth;
} SGSTLVCtx;

static uint64_t SGSTLVReadBE(const uint8_t *b, int n) {
    uint64_t v = 0;
    for (int i = 0; i < n; i++) v = (v << 8) | b[i];
    return v;
}

static id SGSTLVDecodeValue(SGSTLVCtx *c) {
    if (c->end - c->p < 5) return nil;
    uint8_t type = c->p[0];
    uint32_t len = (uint32_t)SGSTLVReadBE(c->p + 1, 4);
    c->p += 5;
    if ((uint64_t)len > (uint64_t)(c->end - c->p)) return nil;

    const uint8_t *payload = c->p;
    const uint8_t *payloadEnd = c->p + len;
    id result = nil;

    switch (type) {
        case SG_STLV_T_MAP: {
            if (++c->depth > SG_STLV_MAX_DEPTH) { c->depth--; return nil; }
            const uint8_t *savedEnd = c->end;
            c->end = payloadEnd; /* frame children to this map */
            NSMutableDictionary *d = [NSMutableDictionary dictionary];
            BOOL ok = YES;
            while (c->p < c->end) {
                if (c->end - c->p < 2) { ok = NO; break; }
                uint16_t klen = (uint16_t)SGSTLVReadBE(c->p, 2);
                c->p += 2;
                if ((uint64_t)klen > (uint64_t)(c->end - c->p)) { ok = NO; break; }
                NSString *key = [[NSString alloc] initWithBytes:c->p length:klen
                                                       encoding:NSUTF8StringEncoding];
                c->p += klen;
                if (!key) { ok = NO; break; }
                id v = SGSTLVDecodeValue(c);
                if (!v) { [key release]; ok = NO; break; }
                [d setObject:v forKey:key];
                [key release];
            }
            c->end = savedEnd;
            c->depth--;
            if (!ok || c->p != payloadEnd) return nil;
            result = d;
            break;
        }
        case SG_STLV_T_ARRAY: {
            if (++c->depth > SG_STLV_MAX_DEPTH) { c->depth--; return nil; }
            const uint8_t *savedEnd = c->end;
            c->end = payloadEnd;
            NSMutableArray *a = [NSMutableArray array];
            BOOL ok = YES;
            while (c->p < c->end) {
                id v = SGSTLVDecodeValue(c);
                if (!v) { ok = NO; break; }
                [a addObject:v];
            }
            c->end = savedEnd;
            c->depth--;
            if (!ok || c->p != payloadEnd) return nil;
            result = a;
            break;
        }
        case SG_STLV_T_STRING: {
            NSString *s = [[NSString alloc] initWithBytes:payload length:len
                                                 encoding:NSUTF8StringEncoding];
            if (!s) return nil; /* invalid UTF-8 */
            result = [s autorelease];
            c->p = payloadEnd;
            break;
        }
        case SG_STLV_T_INT: {
            if (len != 8) return nil;
            int64_t v = (int64_t)SGSTLVReadBE(payload, 8);
            result = [NSNumber numberWithLongLong:v];
            c->p = payloadEnd;
            break;
        }
        case SG_STLV_T_DOUBLE: {
            if (len != 8) return nil;
            uint64_t bits = SGSTLVReadBE(payload, 8);
            double dv;
            memcpy(&dv, &bits, 8); /* bits holds the host-order IEEE-754 pattern */
            if (!isfinite(dv)) return nil;
            result = [NSNumber numberWithDouble:dv];
            c->p = payloadEnd;
            break;
        }
        case SG_STLV_T_BOOL: {
            if (len != 1) return nil;
            uint8_t b = payload[0];
            if (b != 0 && b != 1) return nil;
            result = [NSNumber numberWithBool:(b == 1)];
            c->p = payloadEnd;
            break;
        }
        case SG_STLV_T_NULL: {
            if (len != 0) return nil;
            result = [NSNull null];
            c->p = payloadEnd;
            break;
        }
        case SG_STLV_T_DATA: {
            result = [NSData dataWithBytes:payload length:len];
            c->p = payloadEnd;
            break;
        }
        default:
            return nil; /* unknown type */
    }
    return result;
}

id SG_STLVDecode(const uint8_t *buffer, uint32_t length) {
    if (!buffer || length == 0) return nil;
    SGSTLVCtx c;
    c.p = buffer;
    c.end = buffer + length;
    c.depth = 0;

    id v = SGSTLVDecodeValue(&c);
    if (!v) return nil;
    if (c.p != c.end) return nil;
    if (![v isKindOfClass:[NSDictionary class]]) return nil; /* top must be MAP */
    return v;
}

#pragma mark - Encode (reference / tests)

static void SGSTLVAppendU16(NSMutableData *d, uint16_t v) {
    uint8_t b[2] = { (uint8_t)(v >> 8), (uint8_t)v };
    [d appendBytes:b length:2];
}

static void SGSTLVAppendU32(NSMutableData *d, uint32_t v) {
    uint8_t b[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
    [d appendBytes:b length:4];
}

static void SGSTLVAppendHeader(NSMutableData *out, uint8_t type, NSUInteger payloadLen) {
    [out appendBytes:&type length:1];
    SGSTLVAppendU32(out, (uint32_t)payloadLen);
}

static void SGSTLVAppendBE8(NSMutableData *out, uint64_t u) {
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(u >> (56 - 8 * i));
    [out appendBytes:b length:8];
}

static BOOL SGSTLVEncodeValue(NSMutableData *out, id obj, int depth) {
    if (depth > SG_STLV_MAX_DEPTH) return NO;

    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSMutableData *body = [NSMutableData data];
        NSDictionary *in = (NSDictionary *)obj;
        for (id key in in) {
            if (![key isKindOfClass:[NSString class]]) return NO;
            NSData *kd = [(NSString *)key dataUsingEncoding:NSUTF8StringEncoding];
            if (!kd || kd.length > 0xFFFF) return NO;
            SGSTLVAppendU16(body, (uint16_t)kd.length);
            [body appendData:kd];
            if (!SGSTLVEncodeValue(body, [in objectForKey:key], depth + 1)) return NO;
        }
        SGSTLVAppendHeader(out, SG_STLV_T_MAP, body.length);
        [out appendData:body];
        return YES;
    }
    if ([obj isKindOfClass:[NSArray class]]) {
        NSMutableData *body = [NSMutableData data];
        for (id v in (NSArray *)obj) {
            if (!SGSTLVEncodeValue(body, v, depth + 1)) return NO;
        }
        SGSTLVAppendHeader(out, SG_STLV_T_ARRAY, body.length);
        [out appendData:body];
        return YES;
    }
    if ([obj isKindOfClass:[NSString class]]) {
        NSData *d = [(NSString *)obj dataUsingEncoding:NSUTF8StringEncoding];
        if (!d) d = [NSData data];
        SGSTLVAppendHeader(out, SG_STLV_T_STRING, d.length);
        [out appendData:d];
        return YES;
    }
    if ([obj isKindOfClass:[NSData class]]) {
        SGSTLVAppendHeader(out, SG_STLV_T_DATA, [(NSData *)obj length]);
        [out appendData:(NSData *)obj];
        return YES;
    }
    if ([obj isKindOfClass:[NSNull class]]) {
        SGSTLVAppendHeader(out, SG_STLV_T_NULL, 0);
        return YES;
    }
    if ([obj isKindOfClass:[NSNumber class]]) {
        NSNumber *num = (NSNumber *)obj;
        if (CFGetTypeID((CFTypeRef)num) == CFBooleanGetTypeID()) {
            uint8_t b = [num boolValue] ? 1 : 0;
            SGSTLVAppendHeader(out, SG_STLV_T_BOOL, 1);
            [out appendBytes:&b length:1];
            return YES;
        }
        const char *t = [num objCType];
        if (t && (strcmp(t, "f") == 0 || strcmp(t, "d") == 0)) {
            double dv = [num doubleValue];
            uint64_t bits;
            memcpy(&bits, &dv, 8);
            SGSTLVAppendHeader(out, SG_STLV_T_DOUBLE, 8);
            SGSTLVAppendBE8(out, bits);
            return YES;
        }
        int64_t iv = [num longLongValue];
        SGSTLVAppendHeader(out, SG_STLV_T_INT, 8);
        SGSTLVAppendBE8(out, (uint64_t)iv);
        return YES;
    }
    return NO; /* no STLV representation */
}

NSData *SG_STLVEncode(NSDictionary *root) {
    if (![root isKindOfClass:[NSDictionary class]]) return nil;
    NSMutableData *out = [NSMutableData data];
    if (!SGSTLVEncodeValue(out, root, 0)) return nil;
    return out;
}
