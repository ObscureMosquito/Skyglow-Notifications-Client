#import "SGJSONParser.h"
#import <stdlib.h>
#import <string.h>
#import <errno.h>
#import <math.h>

typedef struct {
    const uint8_t *p;
    const uint8_t *end;
    int depth;
} SGJSONCtx;

static id SGJSONParseValue(SGJSONCtx *c);

static void SGJSONSkipWS(SGJSONCtx *c) {
    while (c->p < c->end) {
        uint8_t ch = *c->p;
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') c->p++;
        else break;
    }
}

static int SGJSONHexNibble(uint8_t ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static BOOL SGJSONReadHex4(SGJSONCtx *c, uint32_t *out) {
    if (c->end - c->p < 4) return NO;
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        int h = SGJSONHexNibble(c->p[i]);
        if (h < 0) return NO;
        v = (v << 4) | (uint32_t)h;
    }
    c->p += 4;
    *out = v;
    return YES;
}

static BOOL SGJSONAppendUTF8(NSMutableData *out, uint32_t cp) {
    uint8_t buf[4];
    NSUInteger n;
    if (cp <= 0x7F) {
        buf[0] = (uint8_t)cp; n = 1;
    } else if (cp <= 0x7FF) {
        buf[0] = (uint8_t)(0xC0 | (cp >> 6));
        buf[1] = (uint8_t)(0x80 | (cp & 0x3F));
        n = 2;
    } else if (cp <= 0xFFFF) {
        buf[0] = (uint8_t)(0xE0 | (cp >> 12));
        buf[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
        buf[2] = (uint8_t)(0x80 | (cp & 0x3F));
        n = 3;
    } else if (cp <= 0x10FFFF) {
        buf[0] = (uint8_t)(0xF0 | (cp >> 18));
        buf[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
        buf[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
        buf[3] = (uint8_t)(0x80 | (cp & 0x3F));
        n = 4;
    } else {
        return NO;
    }
    [out appendBytes:buf length:n];
    return YES;
}

static NSString *SGJSONParseString(SGJSONCtx *c) {
    if (c->p >= c->end || *c->p != '"') return nil;
    c->p++;
    NSMutableData *out = [NSMutableData data];
    while (c->p < c->end) {
        uint8_t ch = *c->p;
        if (ch == '"') {
            c->p++;
            NSString *s = [[NSString alloc] initWithData:out encoding:NSUTF8StringEncoding];
            return [s autorelease];
        }
        if (ch == '\\') {
            c->p++;
            if (c->p >= c->end) return nil;
            uint8_t esc = *c->p++;
            switch (esc) {
                case '"':  [out appendBytes:"\"" length:1]; break;
                case '\\': [out appendBytes:"\\" length:1]; break;
                case '/':  [out appendBytes:"/"  length:1]; break;
                case 'b':  [out appendBytes:"\b" length:1]; break;
                case 'f':  [out appendBytes:"\f" length:1]; break;
                case 'n':  [out appendBytes:"\n" length:1]; break;
                case 'r':  [out appendBytes:"\r" length:1]; break;
                case 't':  [out appendBytes:"\t" length:1]; break;
                case 'u': {
                    uint32_t u;
                    if (!SGJSONReadHex4(c, &u)) return nil;
                    if (u >= 0xD800 && u <= 0xDBFF) {
                        if (c->end - c->p < 2 || c->p[0] != '\\' || c->p[1] != 'u') return nil;
                        c->p += 2;
                        uint32_t lo;
                        if (!SGJSONReadHex4(c, &lo)) return nil;
                        if (lo < 0xDC00 || lo > 0xDFFF) return nil;
                        uint32_t cp = 0x10000u + (((u - 0xD800u) << 10) | (lo - 0xDC00u));
                        if (!SGJSONAppendUTF8(out, cp)) return nil;
                    } else if (u >= 0xDC00 && u <= 0xDFFF) {
                        return nil;
                    } else {
                        if (!SGJSONAppendUTF8(out, u)) return nil;
                    }
                    break;
                }
                default:
                    return nil;
            }
        } else if (ch < 0x20) {
            return nil;
        } else {
            [out appendBytes:&ch length:1];
            c->p++;
        }
    }
    return nil;
}

static NSNumber *SGJSONParseNumber(SGJSONCtx *c) {
    const uint8_t *start = c->p;
    BOOL isReal = NO;

    if (c->p < c->end && *c->p == '-') c->p++;

    if (c->p >= c->end) return nil;
    if (*c->p == '0') {
        c->p++;
    } else if (*c->p >= '1' && *c->p <= '9') {
        while (c->p < c->end && *c->p >= '0' && *c->p <= '9') c->p++;
    } else {
        return nil;
    }

    if (c->p < c->end && *c->p == '.') {
        isReal = YES;
        c->p++;
        if (c->p >= c->end || *c->p < '0' || *c->p > '9') return nil;
        while (c->p < c->end && *c->p >= '0' && *c->p <= '9') c->p++;
    }

    if (c->p < c->end && (*c->p == 'e' || *c->p == 'E')) {
        isReal = YES;
        c->p++;
        if (c->p < c->end && (*c->p == '+' || *c->p == '-')) c->p++;
        if (c->p >= c->end || *c->p < '0' || *c->p > '9') return nil;
        while (c->p < c->end && *c->p >= '0' && *c->p <= '9') c->p++;
    }

    NSUInteger len = (NSUInteger)(c->p - start);
    char buf[40];
    if (len == 0 || len >= sizeof(buf)) return nil;
    memcpy(buf, start, len);
    buf[len] = '\0';

    if (!isReal) {
        char *endp = NULL;
        errno = 0;
        long long ll = strtoll(buf, &endp, 10);
        if (errno == 0 && endp && *endp == '\0') {
            return [NSNumber numberWithLongLong:ll];
        }
    }

    char *endp = NULL;
    errno = 0;
    double d = strtod(buf, &endp);
    if (!endp || *endp != '\0') return nil;
    if (!isfinite(d)) return nil;
    return [NSNumber numberWithDouble:d];
}

static id SGJSONParseLiteral(SGJSONCtx *c) {
    NSUInteger avail = (NSUInteger)(c->end - c->p);
    if (avail >= 4 && memcmp(c->p, "true", 4) == 0)  { c->p += 4; return [NSNumber numberWithBool:YES]; }
    if (avail >= 5 && memcmp(c->p, "false", 5) == 0) { c->p += 5; return [NSNumber numberWithBool:NO]; }
    if (avail >= 4 && memcmp(c->p, "null", 4) == 0)  { c->p += 4; return [NSNull null]; }
    return nil;
}

static NSArray *SGJSONParseArray(SGJSONCtx *c) {
    c->p++;
    if (++c->depth > SG_JSON_MAX_DEPTH) { c->depth--; return nil; }

    NSMutableArray *arr = [NSMutableArray array];
    SGJSONSkipWS(c);
    if (c->p < c->end && *c->p == ']') { c->p++; c->depth--; return arr; }

    for (;;) {
        id v = SGJSONParseValue(c);
        if (!v) { c->depth--; return nil; }
        [arr addObject:v];
        SGJSONSkipWS(c);
        if (c->p >= c->end) { c->depth--; return nil; }
        uint8_t ch = *c->p++;
        if (ch == ',') continue;
        if (ch == ']') { c->depth--; return arr; }
        c->depth--;
        return nil;
    }
}

static NSDictionary *SGJSONParseObject(SGJSONCtx *c) {
    c->p++;
    if (++c->depth > SG_JSON_MAX_DEPTH) { c->depth--; return nil; }

    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    SGJSONSkipWS(c);
    if (c->p < c->end && *c->p == '}') { c->p++; c->depth--; return dict; }

    for (;;) {
        SGJSONSkipWS(c);
        if (c->p >= c->end || *c->p != '"') { c->depth--; return nil; }
        NSString *key = SGJSONParseString(c);
        if (!key) { c->depth--; return nil; }
        SGJSONSkipWS(c);
        if (c->p >= c->end || *c->p++ != ':') { c->depth--; return nil; }
        id v = SGJSONParseValue(c);
        if (!v) { c->depth--; return nil; }
        [dict setObject:v forKey:key];
        SGJSONSkipWS(c);
        if (c->p >= c->end) { c->depth--; return nil; }
        uint8_t ch = *c->p++;
        if (ch == ',') continue;
        if (ch == '}') { c->depth--; return dict; }
        c->depth--;
        return nil;
    }
}

static id SGJSONParseValue(SGJSONCtx *c) {
    SGJSONSkipWS(c);
    if (c->p >= c->end) return nil;
    uint8_t ch = *c->p;
    switch (ch) {
        case '{': return SGJSONParseObject(c);
        case '[': return SGJSONParseArray(c);
        case '"': return SGJSONParseString(c);
        case 't': case 'f': case 'n': return SGJSONParseLiteral(c);
        case '-': return SGJSONParseNumber(c);
        default:
            if (ch >= '0' && ch <= '9') return SGJSONParseNumber(c);
            return nil;
    }
}

id SG_JSONParse(const uint8_t *bytes, NSUInteger length) {
    if (!bytes || length == 0) return nil;
    SGJSONCtx c;
    c.p = bytes;
    c.end = bytes + length;
    c.depth = 0;

    id value = SGJSONParseValue(&c);
    if (!value) return nil;

    SGJSONSkipWS(&c);
    if (c.p != c.end) return nil;

    return value;
}
