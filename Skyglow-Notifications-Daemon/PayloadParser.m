#import "PayloadParser.h"

NSDictionary *SGP_ParseBinaryPayload(const uint8_t *buffer, uint32_t length) {
    if (!buffer || length == 0) return @{};

    NSMutableDictionary *parsedData = [NSMutableDictionary dictionary];
    uint32_t offset = 0;

    while (offset < length) {
        // 1. Ensure we have enough bytes for Type (1) + Length (2)
        if (offset + 3 > length) {
            NSLog(@"[SGPParser] ERROR: Out of bounds reading TLV header at offset %u", offset);
            return nil; // Abort entirely on malformed data
        }

        uint8_t type = buffer[offset];
        
        // Read Big-Endian uint16 length
        uint16_t valLen = (buffer[offset + 1] << 8) | buffer[offset + 2];
        offset += 3;

        // 2. Ensure we have enough bytes for the Value
        if (offset + valLen > length) {
            NSLog(@"[SGPParser] ERROR: Out of bounds reading TLV value (Need %u, Have %u)", valLen, (length - offset));
            return nil; // Abort
        }

        // 3. Extract the data safely
        if (valLen > 0) {
            if (type == SGP_TLV_TYPE_TITLE || type == SGP_TLV_TYPE_BODY || type == SGP_TLV_TYPE_SOUND) {
                // Initialize string directly from the buffer. Fast, minimal overhead.
                NSString *str = [[NSString alloc] initWithBytes:&buffer[offset]
                                                         length:valLen
                                                       encoding:NSUTF8StringEncoding];
                if (str) {
                    if (type == SGP_TLV_TYPE_TITLE) [parsedData setObject:str forKey:@"title"];
                    else if (type == SGP_TLV_TYPE_BODY) [parsedData setObject:str forKey:@"body"];
                    else if (type == SGP_TLV_TYPE_SOUND) [parsedData setObject:str forKey:@"sound"];
                    [str release];
                }
            } else if (type == SGP_TLV_TYPE_CUSTOM_DATA) {
                NSData *data = [NSData dataWithBytes:&buffer[offset] length:valLen];
                [parsedData setObject:data forKey:@"custom_data"];
            }
        }
        
        offset += valLen;
    }

    return parsedData;
}