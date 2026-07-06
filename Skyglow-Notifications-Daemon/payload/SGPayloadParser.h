#ifndef SKYGLOW_SG_PAYLOAD_PARSER_H
#define SKYGLOW_SG_PAYLOAD_PARSER_H

#import <Foundation/Foundation.h>

/** TLV Field Types */
#define SG_TLV_TYPE_TITLE       0x01
#define SG_TLV_TYPE_BODY        0x02
#define SG_TLV_TYPE_SOUND       0x03
#define SG_TLV_TYPE_CUSTOM_DATA 0x04

/**
 * Inner-payload encoding, carried in the S_NOTIFY frame's content_type byte
 * (SGP_NOTIFY_OFF_CONTENT_TYPE).
 *
 * All three encodings describe the SAME object: an APNS-style userInfo
 * dictionary ({ "aps": { ... }, <custom keys> }). They differ only in wire
 * form, and all decode to one canonical NSDictionary via SG_PayloadDecode.
 *
 *   TLV       (0x00) — the original FLAT compact form (title/body/sound/
 *                      custom_data only). Back-compat default: servers that
 *                      predate this change send a zero byte here. Cannot carry
 *                      nested/array structure — kept for legacy senders.
 *   JSON      (0x01) — origin-sent JSON (e.g. an end-to-end encrypted blob the
 *                      relay never sees in the clear). Decoded by SGJSONParser.
 *   Plist     (0x02) — binary or XML property list (NSPropertyListSerialization).
 *   TLVStruct (0x03) — STRUCTURED TLV (SGStructuredTLV): a typed, recursive
 *                      binary encoding that expresses the SAME object graph as
 *                      JSON/plist (nested maps, arrays, typed scalars, data).
 *                      The full-fidelity TLV; prefer it over 0x00 for new
 *                      senders.
 */
typedef enum : uint8_t {
    SGPayloadFormatTLV       = 0x00,
    SGPayloadFormatJSON      = 0x01,
    SGPayloadFormatPlist     = 0x02,
    SGPayloadFormatTLVStruct = 0x03,
} SGPayloadFormat;

/** Sentinel returned by SG_PayloadSniffFormat when the leading bytes match no
 *  known encoding. Never a valid content_type. */
#define SGPayloadFormatUnknown ((SGPayloadFormat)0xFF)

/**
 * Parses an SGP binary payload (TLV format) into a flat dictionary of strings
 * ({title, body, sound, custom_data}). Retained for the TLV path and tests;
 * most callers should use SG_PayloadDecode, which normalizes to APNS form.
 */
NSDictionary *SG_PayloadParseBinaryData(const uint8_t *buffer, uint32_t length);

/**
 * Content-sniffs the leading bytes of an inner payload. This is a cheap
 * cross-check used to catch a content_type byte that disagrees with the actual
 * bytes — it is NOT the security gate (the per-format decoder is). Returns one
 * of the SGPayloadFormat values or SGPayloadFormatUnknown.
 */
SGPayloadFormat SG_PayloadSniffFormat(const uint8_t *buffer, uint32_t length);

/**
 * Decodes a decrypted inner payload of the declared `contentType` into a
 * canonical, plist-safe APNS userInfo dictionary suitable for handing to
 * APSIncomingMessage. Returns nil on any decode/validation failure, an unknown
 * content type, or a content_type that contradicts the sniffed format.
 *
 * The returned dictionary always carries an "aps" dictionary; NSNull and any
 * non-property-list values are stripped so the result survives the binary-plist
 * IPC hop to SpringBoard intact.
 */
NSDictionary *SG_PayloadDecode(const uint8_t *buffer, uint32_t length, uint8_t contentType);

/**
 * Inflates a raw-DEFLATE (windowBits -15, no zlib/gzip wrapper) payload. Used
 * on the SGP_NOTIFY_FLAG_COMPRESSED path AFTER any decryption and BEFORE
 * SG_PayloadDecode; the encoding is format-agnostic (it wraps JSON/plist/TLV
 * alike). Output is hard-capped at `maxOut` bytes as a decompression-bomb guard.
 * Returns an autoreleased NSData, or nil on a corrupt/truncated stream, an empty
 * result, or an expansion that would exceed `maxOut`.
 */
NSData *SG_PayloadInflate(const uint8_t *buffer, uint32_t length, uint32_t maxOut);

#endif