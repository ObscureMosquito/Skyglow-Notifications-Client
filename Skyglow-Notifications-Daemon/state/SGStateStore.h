#ifndef SKYGLOW_SG_STATE_STORE_H
#define SKYGLOW_SG_STATE_STORE_H

#import <Foundation/Foundation.h>

@interface SGStateStore : NSObject

- (BOOL)updateMainPreferences:(void (^)(NSMutableDictionary *preferences))mutation;

#pragma mark - Profile-slot persistence choke points

/** Takes NSData so the caller can wipe the PEM bytes. */
- (BOOL)commitRegistrationForProfileAtIndex:(NSInteger)profileIdx
                              deviceAddress:(NSString *)deviceAddress
                              privateKeyPEM:(NSData *)privateKeyPEM;
- (BOOL)wipeProfileCredentialsAtIndex:(NSInteger)profileIdx;
- (BOOL)saveProfileAtIndex:(NSInteger)profileIdx
             serverAddress:(NSString *)serverAddress
            certificatePEM:(NSString *)certificatePEM
    invalidatedCredentials:(BOOL *)outInvalidatedCredentials;
- (BOOL)setRegistrationIdentityAtIndex:(NSInteger)profileIdx
                           identityPEM:(NSString *)identityPEM;
- (BOOL)setLastRegistrationFailureCode:(uint8_t)code atIndex:(NSInteger)profileIdx;
- (BOOL)removeProfileAtIndex:(NSInteger)profileIdx;
- (BOOL)performSetAppEnabled:(BOOL)enabled
         forBundleIdentifier:(NSString *)bundleID;
- (BOOL)performClearAppIntentForBundleIdentifier:(NSString *)bundleID;
- (BOOL)performDeleteAppStateForBundleIdentifier:(NSString *)bundleID;
- (void)drainDurableEventInbox;

@end

#endif
