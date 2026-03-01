#ifndef SKYGLOW_SG_CONFIGURATION_H
#define SKYGLOW_SG_CONFIGURATION_H

#import <Foundation/Foundation.h>

/**
 * Resolves the root-relative path for rootless jailbreaks.
 */
static inline NSString * SGPath(NSString *path) {
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"]) {
        return [@"/var/jb" stringByAppendingString:path];
    }
    return path;
}


@interface SGConfiguration : NSObject

/**
 * Returns the shared singleton configuration instance.
 */
+ (SGConfiguration *)sharedConfiguration;

@property (nonatomic, copy) NSString *serverAddress;
@property (nonatomic, copy) NSString *serverIPAddress;
@property (nonatomic, copy) NSString *serverPort;

/**
 * Returns YES when the configuration has a valid server address and, if a profile
 * exists, a valid server public key.
 */
@property (nonatomic, readonly) BOOL isValid;

@property (nonatomic, assign) BOOL isEnabled;
@property (nonatomic, assign) BOOL hasProfile;
@property (nonatomic, copy) NSString *deviceAddress;
@property (nonatomic, copy) NSString *privateKeyPEM;
@property (nonatomic, copy) NSString *serverPubKeyPEM;

/**
 * Reloads all configuration values from the on-disk preference plists.
 */
- (void)reloadFromDisk;

@end

#endif