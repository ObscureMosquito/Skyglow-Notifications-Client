#ifndef SKYGLOW_PAYLOAD_PARSER_H
#define SKYGLOW_PAYLOAD_PARSER_H

#include <stdint.h>
#include <stdbool.h>
#include <Foundation/Foundation.h>

// TLV Field Types
#define SGP_TLV_TYPE_TITLE       0x01
#define SGP_TLV_TYPE_BODY        0x02
#define SGP_TLV_TYPE_SOUND       0x03
#define SGP_TLV_TYPE_CUSTOM_DATA 0x04

/**
 * Parses a TLV binary payload into an NSDictionary.
 * * @param buffer Pointer to the start of the data[] segment (offset 70 in S_NOTIFY).
 * @param length The exact length of the data[] segment.
 * @return NSDictionary containing the parsed strings/data, or nil if the payload is malformed.
 */
NSDictionary *SGP_ParseBinaryPayload(const uint8_t *buffer, uint32_t length);

#endif /* SKYGLOW_PAYLOAD_PARSER_H */