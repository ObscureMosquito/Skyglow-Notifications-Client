#ifndef SKYGLOW_SG_JSON_PARSER_H
#define SKYGLOW_SG_JSON_PARSER_H

#import <Foundation/Foundation.h>

/**
 * Strict, self-contained RFC 8259 JSON parser.
 */

/** Maximum object/array nesting depth accepted. APNS payloads are shallow;
 *  this is a stack-overflow guard, not a functional limit. */
#define SG_JSON_MAX_DEPTH 32

/**
 * Parses `length` bytes of UTF-8 JSON into an autoreleased Foundation object
 * graph: NSDictionary, NSArray, NSString, NSNumber (incl. booleans), or
 * NSNull. Returns nil on ANY malformed input. The returned object is
 * autoreleased; retain it to keep it.
 */
id SG_JSONParse(const uint8_t *bytes, NSUInteger length);

#endif
