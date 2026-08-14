#import "SGStructuredTLV.h"
#include "SGByteOrder.h"
#import <CoreFoundation/CoreFoundation.h>
#import <string.h>
#import <math.h>

#pragma mark - Decode

typedef struct {
    const uint8_t *p;
    const uint8_t *end;
    int depth;
} SGSTLVCtx;

static BOOL SGSTLVReadVarint(SGSTLVCtx *c, uint64_t *out) {
    uint64_t v = 0;
    int shift = 0;
    for (int i = 0; i < 10; i++) {
        if (c->p >= c->end) return NO;
        uint8_t b = *c->p++;
        if (shift == 63 && (b & 0x7E)) return NO;
        v |= (uint64_t)(b & 0x7F) << shift;
        if (!(b & 0x80)) { *out = v; return YES; }
        shift += 7;
    }
    return NO;
}

static int64_t SGSTLVZigZagDecode(uint64_t u) {
    return (int64_t)(u >> 1) ^ -(int64_t)(u & 1);
}

static id SGSTLVDecodeValue(SGSTLVCtx *c) {
    if (c->p >= c->end) return nil;
    uint8_t type = *c->p++;

    /* Fixed / self-delimiting types carry no length field. */
    switch (type) {
        case SG_STLV_T_INT: {
            uint64_t u;
            if (!SGSTLVReadVarint(c, &u)) return nil;
            return [NSNumber numberWithLongLong:SGSTLVZigZagDecode(u)];
        }
        case SG_STLV_T_DOUBLE: {
            if (c->end - c->p < 8) return nil;
            uint64_t bits = (uint64_t)SG_DecodeBE64(c->p);
            c->p += 8;
            double dv;
            memcpy(&dv, &bits, 8); /* bits holds the host order IEEE-754 pattern */
            if (!isfinite(dv)) return nil;
            return [NSNumber numberWithDouble:dv];
        }
        case SG_STLV_T_BOOL: {
            if (c->p >= c->end) return nil;
            uint8_t b = *c->p++;
            if (b != 0 && b != 1) return nil;
            return [NSNumber numberWithBool:(b == 1)];
        }
        case SG_STLV_T_NULL:
            return [NSNull null];

        case SG_STLV_T_STRING:
        case SG_STLV_T_DATA:
        case SG_STLV_T_MAP:
        case SG_STLV_T_ARRAY:
            break; /* variable-length: handled below */

        default:
            return nil; /* unknown type */
    }

    /* Variable-length types: read the varint byte-length, frame the payload. */
    uint64_t len;
    if (!SGSTLVReadVarint(c, &len)) return nil;
    if (len > (uint64_t)(c->end - c->p)) return nil;
    const uint8_t *payload = c->p;
    const uint8_t *payloadEnd = c->p + len;

    if (type == SG_STLV_T_STRING) {
        NSString *s = [[NSString alloc] initWithBytes:payload length:(NSUInteger)len
                                             encoding:NSUTF8StringEncoding];
        if (!s) return nil; /* invalid UTF-8 */
        c->p = payloadEnd;
        return [s autorelease];
    }

    if (type == SG_STLV_T_DATA) {
        NSData *d = [NSData dataWithBytes:payload length:(NSUInteger)len];
        c->p = payloadEnd;
        return d;
    }

    if (type == SG_STLV_T_MAP) {
        if (++c->depth > SG_STLV_MAX_DEPTH) { c->depth--; return nil; }
        const uint8_t *savedEnd = c->end;
        c->end = payloadEnd; /* frame children to this map */
        NSMutableDictionary *d = [NSMutableDictionary dictionary];
        BOOL ok = YES;
        while (c->p < c->end) {
            uint64_t klen;
            if (!SGSTLVReadVarint(c, &klen)) { ok = NO; break; }
            if (klen > (uint64_t)(c->end - c->p)) { ok = NO; break; }
            NSString *key = [[NSString alloc] initWithBytes:c->p length:(NSUInteger)klen
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
        return d;
    }

    /* SG_STLV_T_ARRAY */
    {
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
        return a;
    }
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

static void SGSTLVAppendVarint(NSMutableData *out, uint64_t v) {
    uint8_t buf[10];
    int n = 0;
    do {
        uint8_t b = (uint8_t)(v & 0x7F);
        v >>= 7;
        if (v) b |= 0x80;
        buf[n++] = b;
    } while (v);
    [out appendBytes:buf length:n];
}

static uint64_t SGSTLVZigZagEncode(int64_t n) {
    return ((uint64_t)n << 1) ^ (uint64_t)(n >> 63);
}

static void SGSTLVAppendType(NSMutableData *out, uint8_t type) {
    [out appendBytes:&type length:1];
}

static BOOL SGSTLVEncodeValue(NSMutableData *out, id obj, int depth) {
    if (depth > SG_STLV_MAX_DEPTH) return NO;

    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSMutableData *body = [NSMutableData data];
        NSDictionary *in = (NSDictionary *)obj;
        for (id key in in) {
            if (![key isKindOfClass:[NSString class]]) return NO;
            NSData *kd = [(NSString *)key dataUsingEncoding:NSUTF8StringEncoding];
            if (!kd) return NO;
            SGSTLVAppendVarint(body, (uint64_t)kd.length);
            [body appendData:kd];
            if (!SGSTLVEncodeValue(body, [in objectForKey:key], depth + 1)) return NO;
        }
        SGSTLVAppendType(out, SG_STLV_T_MAP);
        SGSTLVAppendVarint(out, (uint64_t)body.length);
        [out appendData:body];
        return YES;
    }
    if ([obj isKindOfClass:[NSArray class]]) {
        NSMutableData *body = [NSMutableData data];
        for (id v in (NSArray *)obj) {
            if (!SGSTLVEncodeValue(body, v, depth + 1)) return NO;
        }
        SGSTLVAppendType(out, SG_STLV_T_ARRAY);
        SGSTLVAppendVarint(out, (uint64_t)body.length);
        [out appendData:body];
        return YES;
    }
    if ([obj isKindOfClass:[NSString class]]) {
        NSData *d = [(NSString *)obj dataUsingEncoding:NSUTF8StringEncoding];
        if (!d) d = [NSData data];
        SGSTLVAppendType(out, SG_STLV_T_STRING);
        SGSTLVAppendVarint(out, (uint64_t)d.length);
        [out appendData:d];
        return YES;
    }
    if ([obj isKindOfClass:[NSData class]]) {
        SGSTLVAppendType(out, SG_STLV_T_DATA);
        SGSTLVAppendVarint(out, (uint64_t)[(NSData *)obj length]);
        [out appendData:(NSData *)obj];
        return YES;
    }
    if ([obj isKindOfClass:[NSNull class]]) {
        SGSTLVAppendType(out, SG_STLV_T_NULL);
        return YES;
    }
    if ([obj isKindOfClass:[NSNumber class]]) {
        NSNumber *num = (NSNumber *)obj;
        if (CFGetTypeID((CFTypeRef)num) == CFBooleanGetTypeID()) {
            uint8_t b = [num boolValue] ? 1 : 0;
            SGSTLVAppendType(out, SG_STLV_T_BOOL);
            [out appendBytes:&b length:1];
            return YES;
        }
        const char *t = [num objCType];
        if (t && (strcmp(t, "f") == 0 || strcmp(t, "d") == 0)) {
            double dv = [num doubleValue];
            uint64_t bits;
            memcpy(&bits, &dv, 8);
            uint8_t b[8];
            SG_EncodeBE64((int64_t)bits, b);
            SGSTLVAppendType(out, SG_STLV_T_DOUBLE);
            [out appendBytes:b length:8];
            return YES;
        }
        int64_t iv = [num longLongValue];
        SGSTLVAppendType(out, SG_STLV_T_INT);
        SGSTLVAppendVarint(out, SGSTLVZigZagEncode(iv));
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
