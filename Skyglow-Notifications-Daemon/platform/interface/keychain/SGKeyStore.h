#ifndef SKYGLOW_SG_KEY_STORE_H
#define SKYGLOW_SG_KEY_STORE_H

#import <Foundation/Foundation.h>

@protocol SGKeyStore <NSObject>
- (BOOL)storeKeyData:(NSData *)pemData forProfile:(NSInteger)profileIndex;
- (BOOL)copyKeyData:(NSMutableData **)outPEMData forProfile:(NSInteger)profileIndex;
- (BOOL)deleteKeyForProfile:(NSInteger)profileIndex;
- (BOOL)rewrapKeyForPreUnlockAccessForProfile:(NSInteger)profileIndex found:(BOOL *)outFound;
@end

#endif
