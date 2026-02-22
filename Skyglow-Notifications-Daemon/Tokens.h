#ifndef SKYGLOW_TOKENS_H
#define SKYGLOW_TOKENS_H

#import <Foundation/Foundation.h>

@interface Tokens : NSObject

- (NSData *)getDeviceToken:(NSString *)bundleID error:(NSError **)outError;
- (BOOL)removeDeviceTokenForBundleId:(NSString *)bundleId reason:(NSString *)reason;

@end

#endif /* SKYGLOW_TOKENS_H */