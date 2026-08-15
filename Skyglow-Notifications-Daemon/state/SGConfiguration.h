#ifndef SKYGLOW_SG_CONFIGURATION_H
#define SKYGLOW_SG_CONFIGURATION_H

#import <Foundation/Foundation.h>
#import "SGSharedConstants.h"
#include <TargetConditionals.h>

#define SG_MACOS_ROOT @"/usr/local/var/skyglow"

/** resolves a system root relative constant to its real path. */
static inline NSString * SGPath(NSString *path) {
#if TARGET_OS_OSX
    return [SG_MACOS_ROOT stringByAppendingString:path];
#else
    static int _sgPathIsRootless = -1;
    if (__builtin_expect(_sgPathIsRootless < 0, 0)) {
        _sgPathIsRootless = [[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"] ? 1 : 0;
    }
    return _sgPathIsRootless ? [@"/var/jb" stringByAppendingString:path] : path;
#endif
}

void SGEnsureRuntimeDirectories(void);

static inline BOOL SGProfileIndexIsValid(NSInteger profileIdx) {
    return profileIdx >= 1 && profileIdx <= SG_PROFILE_INDEX_MAX;
}

static inline NSString *SGProfilePlistPathForIndex(NSInteger profileIdx) {
    return SGPath([NSString stringWithFormat:
        SG_PROFILE_PLIST_FORMAT, (long)profileIdx]);
}

static inline NSString *SGProfileCertificatePathForIndex(NSInteger profileIdx) {
    return [NSString stringWithFormat:@"%@/profile%ld-server.pem",
            SG_PROFILE_STATE_DIRECTORY, (long)profileIdx];
}

static inline NSString *SGProfileRegIdentityPathForIndex(NSInteger profileIdx) {
    return [NSString stringWithFormat:@"%@/profile%ld-reg-identity.pem",
            SG_PROFILE_STATE_DIRECTORY, (long)profileIdx];
}


@interface SGConfiguration : NSObject

+ (SGConfiguration *)sharedConfiguration;

@property (nonatomic, readonly, copy) NSString *serverAddress;
@property (nonatomic, readonly) BOOL isValid;
@property (nonatomic, readonly) BOOL isEnabled;
@property (nonatomic, readonly) BOOL hasProfile;
@property (nonatomic, readonly) NSInteger logLevel;
@property (nonatomic, readonly, copy) NSString *deviceAddress;
@property (nonatomic, readonly) NSData *privateKeyPEM;
@property (nonatomic, readonly, copy) NSString *serverPubKeyPEM;
@property (nonatomic, readonly, copy) NSString *registrationIdentityPEM;
@property (nonatomic, readonly) NSInteger activeProfileIndex;

- (void)reloadFromDisk;

@end

#endif
