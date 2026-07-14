#ifndef SKYGLOW_SG_STATE_STORE_H
#define SKYGLOW_SG_STATE_STORE_H

#import <Foundation/Foundation.h>

/**
 * SGStateStore is the daemon-side persistence coordinator for profile slots,
 * app/provider intent, and missed-uninstall recovery.
 */
@interface SGStateStore : NSObject

/* Main-prefs read-modify-write choke point */
- (BOOL)updateMainPreferences:(void (^)(NSMutableDictionary *preferences))mutation;

#pragma mark - Profile-slot persistence choke points

/**
 * Commits a completed server registration: stores the private key in the
 * keychain, then persists the issued device address.
 */
- (BOOL)commitRegistrationForProfileAtIndex:(NSInteger)profileIdx
                              deviceAddress:(NSString *)deviceAddress
                              privateKeyPEM:(NSString *)privateKeyPEM;

/**
 * Deletes the slot's private key and strips its issued credentials
 * (device_address / legacy privateKey) from the profile plist.
 */
- (BOOL)wipeProfileCredentialsAtIndex:(NSInteger)profileIdx;

/**
 * Persists a validated server address and (optionally) a new pinned
 * certificate for the slot.
 */
- (BOOL)saveProfileAtIndex:(NSInteger)profileIdx
             serverAddress:(NSString *)serverAddress
            certificatePEM:(NSString *)certificatePEM
    invalidatedCredentials:(BOOL *)outInvalidatedCredentials;

/* Stores or removes the slot's operator-issued registration identity and its profile-plist pointer */
- (BOOL)setRegistrationIdentityAtIndex:(NSInteger)profileIdx
                           identityPEM:(NSString *)identityPEM;

/**
 * Removes the slot, keychain entry, certificate, and operational database
 * state as one serialized operation.
 */
- (BOOL)removeProfileAtIndex:(NSInteger)profileIdx;

/* Applies one platform-neutral per-app intent from live IPC */
- (BOOL)performSetAppEnabled:(BOOL)enabled
         forBundleIdentifier:(NSString *)bundleID;

/*
 * Clears the persisted provider choice and mutes any existing token row so the
 * server stops treating the bundle as Skyglow-routed.
 */
- (BOOL)performClearAppIntentForBundleIdentifier:(NSString *)bundleID;

/* Clears daemon-owned operational and intent state after an app disappears. */
- (BOOL)performDeleteAppStateForBundleIdentifier:(NSString *)bundleID;

/* Schedules idempotent processing of missed-uninstall inbox files. */
- (void)drainDurableEventInbox;

@end

#endif
