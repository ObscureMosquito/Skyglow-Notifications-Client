#ifndef SKYGLOW_SG_STRUCTURED_TLV_H
#define SKYGLOW_SG_STRUCTURED_TLV_H

#import <Foundation/Foundation.h>

#define SG_STLV_T_MAP     0x01
#define SG_STLV_T_ARRAY   0x02
#define SG_STLV_T_STRING  0x03
#define SG_STLV_T_INT     0x04
#define SG_STLV_T_DOUBLE  0x05
#define SG_STLV_T_BOOL    0x06
#define SG_STLV_T_NULL    0x07
#define SG_STLV_T_DATA    0x08

/** Maximum container nesting accepted. */
#define SG_STLV_MAX_DEPTH 32

/** Decodes an STLV document into an autoreleased Foundation object graph.*/
id SG_STLVDecode(const uint8_t *buffer, uint32_t length);

/** Encodes a Foundation object graph into STLV */
NSData *SG_STLVEncode(NSDictionary *root);

#endif
