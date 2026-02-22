#ifndef SKYGLOW_SG_CONFIGURATION_H
#define SKYGLOW_SG_CONFIGURATION_H

#import <Foundation/Foundation.h>

@interface SGConfiguration : NSObject

/// The singleton instance for configuration management.
+ (SGConfiguration *)sharedConfiguration;

@property (nonatomic, copy) NSString *serverAddress;
@property (nonatomic, copy) NSString *serverIPAddress;
@property (nonatomic, copy) NSString *serverPort;

@end

#endif /* SKYGLOW_SG_CONFIGURATION_H */