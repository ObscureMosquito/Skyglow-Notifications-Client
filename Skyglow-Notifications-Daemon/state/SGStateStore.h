#ifndef SKYGLOW_SG_STATE_STORE_H
#define SKYGLOW_SG_STATE_STORE_H

#import <Foundation/Foundation.h>

/**
 * SGStateStore is the daemon-side persistence coordinator for profile slots,
 * app/provider intent, and missed-uninstall recovery.  It is deliberately not
 * a public read-model publisher and not a SpringBoard adapter.
 */
@interface SGStateStore : NSObject

/**
 * Main-prefs read-modify-write choke point.  The block receives the current
 * (mutable) preferences; the store persists them atomically afterwards.  This
 * is the only place the shared prefs plist is written.
 */
- (BOOL)updateMainPreferences:(void (^)(NSMutableDictionary *preferences))mutation;

#pragma mark - Profile-slot persistence choke points

/*
 * Everything below is serialized on the store lock: profile plists and their
 * pinned-certificate files have exactly one writer.  SGDaemon keeps the
 * orchestration around these calls (validation, config reload, FSM events,
 * operational-DB cleanup) but owns no profile bytes on disk.
 */

/**
 * Commits a completed server registration: stores the private key in the
 * keychain, then persists the issued device address.  The key is removed
 * again if the plist write fails, so a half-committed registration never
 * survives.
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
 * certificate for the slot.  The certificate is published with the same
 * fsync+rename discipline as the plists and rolled back if the plist commit
 * fails.  When the address or certificate changes, issued credentials are
 * invalidated (plist entries removed, keychain key deleted) and
 * *outInvalidatedCredentials is set so the caller can clear operational
 * state.  Pass nil certificatePEM to keep the existing certificate.
 */
- (BOOL)saveProfileAtIndex:(NSInteger)profileIdx
             serverAddress:(NSString *)serverAddress
            certificatePEM:(NSString *)certificatePEM
    invalidatedCredentials:(BOOL *)outInvalidatedCredentials;

/**
 * Removes the slot entirely: visible profile plist first, then credential
 * sidecars.  A partial failure can leave harmless orphaned sidecars, but not a
 * visible profile that has already lost its key or certificate.
 */
- (BOOL)removeProfileAtIndex:(NSInteger)profileIdx;

/**
 * Applies one platform-neutral per-app intent from live IPC.  Mints a token
 * when enabling, syncs the DB mute flag, and writes the durable appStatus
 * choice.
 */
- (BOOL)performSetAppEnabled:(BOOL)enabled
         forBundleIdentifier:(NSString *)bundleID;

/**
 * Clears the persisted provider choice and mutes any existing token row so the
 * server stops treating the bundle as Skyglow-routed.  No platform APIs are
 * invoked.
 */
- (BOOL)performClearAppIntentForBundleIdentifier:(NSString *)bundleID;

/** Clears daemon-owned operational and intent state after an app disappears. */
- (BOOL)performDeleteAppStateForBundleIdentifier:(NSString *)bundleID;

/** Schedules idempotent processing of missed-uninstall inbox files. */
- (void)drainDurableEventInbox;

@end

#endif
