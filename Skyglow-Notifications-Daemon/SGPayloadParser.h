#ifndef SKYGLOW_SG_PAYLOAD_PARSER_H
#define SKYGLOW_SG_PAYLOAD_PARSER_H

#import <Foundation/Foundation.h>

/** TLV Field Types */
#define SG_TLV_TYPE_TITLE       0x01
#define SG_TLV_TYPE_BODY        0x02
#define SG_TLV_TYPE_SOUND       0x03
#define SG_TLV_TYPE_CUSTOM_DATA 0x04

/**
 * Parses an SGP binary payload (TLV format) into a dictionary of strings.
 */
NSDictionary *SG_PayloadParseBinaryData(const uint8_t *buffer, uint32_t length);

#endif