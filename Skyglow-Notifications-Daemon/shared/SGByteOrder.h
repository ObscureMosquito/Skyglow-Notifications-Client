#ifndef SKYGLOW_SG_BYTE_ORDER_H
#define SKYGLOW_SG_BYTE_ORDER_H

#include <stdint.h>

/** Alignment safe big endian codecs shared by the wire and payload layers. */

static inline void SG_EncodeBE16(uint16_t v, uint8_t out[2]) {
    out[0] = (uint8_t)(v >> 8);
    out[1] = (uint8_t)(v & 0xFF);
}

static inline uint16_t SG_DecodeBE16(const uint8_t p[2]) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline uint32_t SG_DecodeBE32(const uint8_t p[4]) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void SG_EncodeBE64(int64_t v, uint8_t out[8]) {
    uint64_t u = (uint64_t)v;
    out[0]=(uint8_t)(u>>56); out[1]=(uint8_t)(u>>48);
    out[2]=(uint8_t)(u>>40); out[3]=(uint8_t)(u>>32);
    out[4]=(uint8_t)(u>>24); out[5]=(uint8_t)(u>>16);
    out[6]=(uint8_t)(u>> 8); out[7]=(uint8_t)(u);
}

static inline int64_t SG_DecodeBE64(const uint8_t p[8]) {
    uint64_t u = 0;
    for (int i = 0; i < 8; i++) u = (u << 8) | p[i];
    return (int64_t)u;
}

#endif
