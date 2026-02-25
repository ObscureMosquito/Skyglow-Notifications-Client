#ifndef SKYGLOW_SG_CONFIGURATION_H
#define SKYGLOW_SG_CONFIGURATION_H

#import <Foundation/Foundation.h>

/// Resolves the root-relative path for rootless jailbreaks.
/// Every file in the daemon uses this single shared definition.
static inline NSString * SGPath(NSString *path) {
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"]) {
        return [@"/var/jb" stringByAppendingString:path];
    }
    return path;
}


@interface SGConfiguration : NSObject

/// The singleton instance for configuration management.
+ (SGConfiguration *)sharedConfiguration;

@property (nonatomic, copy) NSString *serverAddress;
@property (nonatomic, copy) NSString *serverIPAddress;
@property (nonatomic, copy) NSString *serverPort;
@property (nonatomic, readonly) BOOL isValid;
@property (nonatomic, assign) BOOL isEnabled;
@property (nonatomic, assign) BOOL hasProfile;
@property (nonatomic, copy) NSString *deviceAddress;
@property (nonatomic, copy) NSString *privateKeyPEM;
@property (nonatomic, copy) NSString *serverPubKeyPEM;

- (void)reloadFromDisk;

@end

#endif /* SKYGLOW_SG_CONFIGURATION_H */