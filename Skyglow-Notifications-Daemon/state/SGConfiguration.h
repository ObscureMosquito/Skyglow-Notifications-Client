#ifndef SKYGLOW_SG_CONFIGURATION_H
#define SKYGLOW_SG_CONFIGURATION_H

#import <Foundation/Foundation.h>
#import "SGSharedConstants.h"
#import "SGPlatformConstants.h"

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
