#ifndef SKYGLOW_SG_STRUCTURED_TLV_H
#define SKYGLOW_SG_STRUCTURED_TLV_H

#import <Foundation/Foundation.h>

/**
 * Structured TLV (STLV) — a typed, recursive binary encoding of the same
 * object model JSON and plist describe. Tuned for minimum size: only the
 * variable-length types carry a length, and that length (plus every integer)
 * is a varint, so small values cost 1-2 bytes instead of a fixed 4-8.
 *
 *  VARINT (unsigned LEB128): base-128, little-endian groups. Each byte holds 7
 *  value bits in its low bits; the high bit (0x80) means "another byte follows".
 *  Decoders accept at most 10 bytes (a full 64-bit value) and reject anything
 *  that would overflow 64 bits. Encoders emit the minimal number of bytes.
 *
 *  Every VALUE is:
 *
 *      type    : uint8
 *      [length : varint]   — ONLY for the variable-length types (MAP, ARRAY,
 *                            STRING, DATA); it is the byte count of `payload`.
 *      payload : interpretation depends on type (see below)
 *
 *  The fixed/self-delimiting types carry NO length field — their size is fixed
 *  by the type, or (for INT) self-described by the varint itself.
 *
 *  Types:
 *
 *    0x01 MAP    length = byte count of the entries that follow.
 *               payload = zero or more ENTRIES packed back to back until the
 *               declared length is exhausted. Each ENTRY is:
 *                   keyLen : varint
 *                   key    : keyLen bytes, UTF-8 (NOT NUL-terminated)
 *                   value  : a VALUE (recursive)
 *               Duplicate keys: last one wins.
 *
 *    0x02 ARRAY length = byte count of the values that follow.
 *               payload = zero or more VALUEs packed back to back until the
 *               declared length is exhausted.
 *
 *    0x03 STRING length = byte count.
 *               payload = UTF-8 bytes (NOT NUL-terminated). Must be valid UTF-8.
 *
 *    0x04 INT   NO length. payload = one zig-zag varint of a signed int64.
 *               Zig-zag maps n -> (n << 1) ^ (n >> 63) so small-magnitude
 *               values of either sign stay short (e.g. 0,-1,1,-2 -> 0,1,2,3).
 *
 *    0x05 DOUBLE NO length. payload = exactly 8 bytes, the IEEE-754 binary64
 *               bit pattern, big-endian. Non-finite (NaN/Inf) is rejected.
 *
 *    0x06 BOOL  NO length. payload = exactly 1 byte: 0x00 false, 0x01 true.
 *
 *    0x07 NULL  NO length, NO payload.
 *
 *    0x08 DATA  length = byte count.
 *               payload = raw bytes (TLV-native; JSON would have to base64 this).
 *
 *  The top-level VALUE MUST be a MAP. Container lengths must frame their
 *  children exactly — a child that would read past the container's declared
 *  length, or leftover bytes inside it, is a hard error.
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
