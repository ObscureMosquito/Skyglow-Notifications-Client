#ifndef SKYGLOW_SG_STATE_STORE_H
#define SKYGLOW_SG_STATE_STORE_H

#import <Foundation/Foundation.h>

/**
 * SGStateStore — the daemon's single-writer authority over persistent app and
 * event state, and the publisher of the sanitized read model.
 *
 * Extracted out of SGDaemon so the daemon file keeps its true purpose (the
 * connection state machine + delivery) and everything that owns *persistence*
 * lives here: the main-prefs plist writes, the per-app intent transactions
 * (DB mute/token + plist appStatus), the durable write-ahead inbox, and the
 * public-state snapshot consumers read.  This class is platform-neutral — it
 * touches no SpringBoard/UIKit API and no FSM — so it compiles and behaves
 * identically on iOS and macOS.
 *
 * Threading: every main-prefs write funnels through -updateMainPreferences:,
 * which serialises read-modify-write under the store's own lock, making the
 * store the single code-level writer of that plist.  Inbox drains and snapshot
 * publications run on a private serial queue.  All apply paths (IPC handlers
 * and the durable-inbox replay) converge on the same performSet* methods, so a
 * command has identical, idempotent effect whether applied live or replayed.
 */
@interface SGStateStore : NSObject

/**
 * Main-prefs read-modify-write choke point.  The block receives the current
 * (mutable) preferences; the store persists them atomically afterwards.  This
 * is the only place the shared prefs plist is written.
 */
- (BOOL)updateMainPreferences:(void (^)(NSMutableDictionary *preferences))mutation;

/**
 * Applies one platform-neutral per-app intent.  Shared by the IPC handlers and
 * the durable inbox so retries are idempotent and use identical DB/plist
 * transaction semantics.  Mints a token when enabling, syncs the DB mute flag,
 * writes the durable appStatus choice, and republishes the read model.
 */
- (BOOL)performSetAppEnabled:(BOOL)enabled
         forBundleIdentifier:(NSString *)bundleID;

/** Removes only the persisted provider choice; no platform APIs are invoked. */
- (BOOL)performClearAppIntentForBundleIdentifier:(NSString *)bundleID;

/** Clears daemon-owned operational and intent state after an app disappears. */
- (BOOL)performDeleteAppStateForBundleIdentifier:(NSString *)bundleID;

/**
 * Per-bundle operational cleanup: drops the DB row and scrubs queued local
 * pending deliveries.  Idempotent.  Does not flush the server filter or clear
 * pendingDeletions.  Used by both the delete path and reload-time reconcile.
 */
- (BOOL)runDeletionCascadeForBundleIdentifier:(NSString *)bundleID;

/**
 * Atomically removes bundles from the plist's pendingDeletions list once their
 * cleanup has completed.  No-op if the field is missing or none are present.
 */
- (BOOL)clearPendingDeletionsForBundleIdentifiers:(NSArray *)bundles;
- (BOOL)clearPendingDeletionForBundleIdentifier:(NSString *)bundleID;

/** Schedules idempotent processing of generic write-ahead event files. */
- (void)drainDurableEventInbox;

/** Schedules publication of the sanitized, read-only state snapshot. */
- (void)schedulePublicStateSnapshot;

@end

#endif
