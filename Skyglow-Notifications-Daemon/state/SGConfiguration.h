#ifndef SKYGLOW_SG_CONFIGURATION_H
#define SKYGLOW_SG_CONFIGURATION_H

#import <Foundation/Foundation.h>
#import "SGSharedConstants.h"
#include <TargetConditionals.h>

/**
 * Base directory the whole runtime tree lives under on macOS.
 */
#define SG_MACOS_ROOT @"/usr/local/var/skyglow"

/**
 * Resolves a system-root-relative constant to its real on-disk path.
 */
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

/**
 * Creates the runtime directory tree (log, pid, database parents) if missing.
 */
void SGEnsureRuntimeDirectories(void);


@interface SGConfiguration : NSObject

/**
 * Returns the shared singleton configuration instance.
 */
+ (SGConfiguration *)sharedConfiguration;

@property (nonatomic, readonly, copy) NSString *serverAddress;
@property (nonatomic, copy) NSString *serverIPAddress;
@property (nonatomic, copy) NSString *serverPort;

/**
 * Returns YES when the active profile exists and has a server address plus
 * readable server public key.
 */
@property (nonatomic, readonly) BOOL isValid;

@property (nonatomic, readonly) BOOL isEnabled;
@property (nonatomic, readonly) BOOL hasProfile;

/**
 * Minimum log level read from the "logLevel" key of the main prefs plist
 * (com.skyglow.sndp).  Encoding matches SGLogLevel: 0=Error, 1=Warn,
 * 2=Info (default), 3=Debug, 4=Trace.  Absent or out-of-range values
 * resolve to Info so a freshly-installed daemon logs at the same volume
 * the codebase used to with NSLog.
 */
@property (nonatomic, readonly) NSInteger logLevel;
@property (nonatomic, readonly, copy) NSString *deviceAddress;
/* PEM-encoded RSA private key as raw bytes.  Returned as an immutable snapshot;
 * the backing store is zeroed on reload/dealloc so the key never lingers. */
@property (nonatomic, readonly) NSData *privateKeyPEM;
@property (nonatomic, readonly, copy) NSString *serverPubKeyPEM;
/* Optional operator-issued client cert */
@property (nonatomic, readonly, copy) NSString *registrationIdentityPEM;

/**
 * 1-based index of the active profile (1–5).  Defaults to 1.
 */
@property (nonatomic, readonly) NSInteger activeProfileIndex;

/**
 * Reloads all configuration values from the on-disk preference plists.
 */
- (void)reloadFromDisk;

@end

#endif
