#import "SGPayloadParser.h"

NSDictionary *SG_PayloadParseBinaryData(const uint8_t *buffer, uint32_t length) {
    if (!buffer || length == 0) return @{};

    NSMutableDictionary *parsedData = [NSMutableDictionary dictionary];
    uint32_t offset = 0;

    while (offset < length) {
        if ((uint64_t)offset + 3 > length) return nil; // Header truncated

        uint8_t type = buffer[offset];
        uint16_t valLen = (buffer[offset + 1] << 8) | buffer[offset + 2];
        offset += 3;

        if ((uint64_t)offset + valLen > length) return nil; // Value out of bounds

        if (valLen > 0) {
            if (type == SG_TLV_TYPE_TITLE || type == SG_TLV_TYPE_BODY || type == SG_TLV_TYPE_SOUND) {
                NSString *str = [[NSString alloc] initWithBytes:&buffer[offset]
                                                         length:valLen
                                                       encoding:NSUTF8StringEncoding];
                if (str) {
                    NSString *key = (type == SG_TLV_TYPE_TITLE) ? @"title" : 
                                    (type == SG_TLV_TYPE_BODY) ? @"body" : @"sound";
                    [parsedData setObject:str forKey:key];
                    [str release];
                }
            } else if (type == SG_TLV_TYPE_CUSTOM_DATA) {
                NSData *data = [NSData dataWithBytes:&buffer[offset] length:valLen];
                [parsedData setObject:data forKey:@"custom_data"];
            }
        }
        offset += valLen;
    }

    return parsedData;
}