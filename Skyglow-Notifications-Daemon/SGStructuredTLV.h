#ifndef SKYGLOW_SG_STRUCTURED_TLV_H
#define SKYGLOW_SG_STRUCTURED_TLV_H

#import <Foundation/Foundation.h>

/**
 * Structured TLV (STLV) — a typed, recursive binary encoding of the same
 * object model JSON and plist describe.
 *
 *  Every VALUE is:
 *
 *      type    : uint8
 *      length  : uint32, big-endian   (byte count of payload)
 *      payload : `length` bytes        (interpretation depends on type)
 *
 *  Types:
 *
 *    0x01 MAP    payload = zero or more ENTRIES, packed back to back until the
 *               payload is exhausted. Each ENTRY is:
 *                   keyLen : uint16, big-endian
 *                   key    : keyLen bytes, UTF-8 (NOT NUL-terminated)
 *                   value  : a VALUE (recursive)
 *               Duplicate keys: last one wins.
 *
 *    0x02 ARRAY payload = zero or more VALUEs packed back to back until the
 *               payload is exhausted.
 *
 *    0x03 STRING payload = UTF-8 bytes (NOT NUL-terminated). Must be valid UTF-8.
 *
 *    0x04 INT   payload = exactly 8 bytes, signed two's-complement int64,
 *               big-endian.
 *
 *    0x05 DOUBLE payload = exactly 8 bytes, the IEEE-754 binary64 bit pattern,
 *               big-endian. Non-finite values (NaN/Inf) are rejected.
 *
 *    0x06 BOOL  payload = exactly 1 byte: 0x00 false, 0x01 true.
 *
 *    0x07 NULL  payload length must be 0.
 *
 *    0x08 DATA  payload = raw bytes (TLV-native; JSON would have to base64 this).
 *
 *  The top-level VALUE MUST be a MAP. Container payload lengths must frame
 *  their children exactly — a child that would read past the container's
 *  declared length, or leftover bytes inside it, is a hard error.
 */

#define SG_STLV_T_MAP     0x01
#define SG_STLV_T_ARRAY   0x02
#define SG_STLV_T_STRING  0x03
#define SG_STLV_T_INT     0x04
#define SG_STLV_T_DOUBLE  0x05
#define SG_STLV_T_BOOL    0x06
#define SG_STLV_T_NULL    0x07
#define SG_STLV_T_DATA    0x08

/** Maximum container nesting accepted. Matches the JSON parser's guard; a
 *  stack-overflow backstop, not a functional limit. */
#define SG_STLV_MAX_DEPTH 32

/**
 * Decodes an STLV document into an autoreleased Foundation object graph. The
 * top-level value must be a MAP, so the return is an NSDictionary (or nil on
 * any malformed input, unknown type, framing error, bad UTF-8, non-finite
 * double, or trailing bytes). Values are NSDictionary/NSArray/NSString/
 * NSNumber/NSNull/NSData.
 */
id SG_STLVDecode(const uint8_t *buffer, uint32_t length);

/**
 * Encodes a Foundation object graph (rooted at an NSDictionary) into STLV.
 * Mainly a reference encoder for tests and for the server maintainer; the
 * daemon itself only ever decodes. Returns nil if the graph contains a value
 * that has no STLV representation. NSNumber booleans are emitted as BOOL,
 * float/double as DOUBLE, everything else integral as INT.
 */
NSData *SG_STLVEncode(NSDictionary *root);

#endif
