#ifndef SKYGLOW_SG_JSON_PARSER_H
#define SKYGLOW_SG_JSON_PARSER_H

#import <Foundation/Foundation.h>

/** Maximum object/array nesting depth accepted. APNS payloads are shallow;
 *  this is a stack-overflow guard, not a functional limit. */
#define SG_JSON_MAX_DEPTH 32

/** Returns nil on malformed input. Result is autoreleased. */
id SG_JSONParse(const uint8_t *bytes, NSUInteger length);

/** Advances past JSON whitespace (space, tab, CR, LF). */
const uint8_t *SG_JSONSkipWhitespace(const uint8_t *p, const uint8_t *end);

#endif
