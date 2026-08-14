#ifndef SKYGLOW_SG_PAYLOAD_PARSER_H
#define SKYGLOW_SG_PAYLOAD_PARSER_H

#import <Foundation/Foundation.h>

#define SG_TLV_TYPE_TITLE       0x01
#define SG_TLV_TYPE_BODY        0x02
#define SG_TLV_TYPE_SOUND       0x03
#define SG_TLV_TYPE_CUSTOM_DATA 0x04

typedef enum : uint8_t {
    SGPayloadFormatTLV       = 0x00,
    SGPayloadFormatJSON      = 0x01,
    SGPayloadFormatPlist     = 0x02,
    SGPayloadFormatTLVStruct = 0x03,
} SGPayloadFormat;

/** Sentinel returned by SG_PayloadSniffFormat when the leading bytes match no known encoding */
#define SGPayloadFormatUnknown ((SGPayloadFormat)0xFF)

/** Decodes a decrypted inner payload of the declared `contentType` into a APNS dict */
NSDictionary *SG_PayloadDecode(const uint8_t *buffer, uint32_t length, uint8_t contentType);

/** Inflates a raw-DEFLATE payload, duh */
NSData *SG_PayloadInflate(const uint8_t *buffer, uint32_t length, uint32_t maxOut);

#endif