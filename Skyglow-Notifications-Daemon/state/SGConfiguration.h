#ifndef SKYGLOW_SG_CONFIGURATION_H
#define SKYGLOW_SG_CONFIGURATION_H

#import <Foundation/Foundation.h>
#import "SGSharedConstants.h"
#include <TargetConditionals.h>

#define SG_MACOS_ROOT @"/usr/local/var/skyglow"

/** Resolves a system-root-relative constant to its real on-disk path. */
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


@interface SGConfiguration : NSObject

+ (SGConfiguration *)sharedConfiguration;

@property (nonatomic, readonly, copy) NSString *serverAddress;
@property (nonatomic, copy) NSString *serverIPAddress;
@property (nonatomic, copy) NSString *serverPort;

/** YES when the active profile has a server address and readable server public key. */
@property (nonatomic, readonly) BOOL isValid;

@property (nonatomic, readonly) BOOL isEnabled;
@property (nonatomic, readonly) BOOL hasProfile;

/** Encoding matches SGLogLevel (0-4). Defaults to Info. */
@property (nonatomic, readonly) NSInteger logLevel;
@property (nonatomic, readonly, copy) NSString *deviceAddress;
/** Immutable snapshot; backing store is zeroed on reload/dealloc. */
@property (nonatomic, readonly) NSData *privateKeyPEM;
@property (nonatomic, readonly, copy) NSString *serverPubKeyPEM;
@property (nonatomic, readonly, copy) NSString *registrationIdentityPEM;

/** 1-based (1-5). Defaults to 1. */
@property (nonatomic, readonly) NSInteger activeProfileIndex;

- (void)reloadFromDisk;

@end

#endif
