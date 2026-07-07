#ifndef SKYGLOW_SG_STATE_STORE_H
#define SKYGLOW_SG_STATE_STORE_H

#import <Foundation/Foundation.h>

/**
 * SGStateStore is the daemon-side persistence coordinator for app/provider
 * intent and missed-uninstall recovery.  It is deliberately not a public
 * read-model publisher and not a SpringBoard adapter.
 */
@interface SGStateStore : NSObject

/**
 * Main-prefs read-modify-write choke point.  The block receives the current
 * (mutable) preferences; the store persists them atomically afterwards.  This
 * is the only place the shared prefs plist is written.
 */
- (BOOL)updateMainPreferences:(void (^)(NSMutableDictionary *preferences))mutation;

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
