#ifndef SKYGLOW_SG_DAEMON_H
#define SKYGLOW_SG_DAEMON_H

#import <Foundation/Foundation.h>
#import "SGProtocolHandler.h"
#import "SGStatusServer.h"
#import "SGControlChannelProtocol.h"

/** State Machine Timing Constants */
#define SG_INITIAL_BACKOFF_SECONDS        2
#define SG_MAX_BACKOFF_SECONDS            600
#define SG_MAX_CONSECUTIVE_FAILURES       14    // ~67 min total retry then stop
#define SG_MAX_JITTER_SECONDS             5
#define SG_AUTH_FAILURE_BACKOFF_SECONDS   30

typedef NS_ENUM(NSInteger, SGEvent) {
    // External Triggers
    SGEventStartRequested,
    SGEventStopRequested,
    SGEventConfigReloaded,
    SGEventNetworkUp,
    SGEventNetworkDown,
    
    // Asynchronous Internal Results
    SGEventDNSResolved,
    SGEventDNSFailed,
    SGEventConnectSuccess,
    SGEventConnectFailed,
    SGEventAuthSuccess,
    SGEventAuthFailed,
    SGEventReplaced,
    SGEventDisconnected,
    SGEventVersionMismatch,
    SGEventBackoffTimerFired,

    // System Power
    SGEventSystemDidWake,   // Device woke from deep sleep — retry if circuit-open
    SGEventAuthTimeout      // Auth timer expired (not an explicit server rejection)
};

@class SGControlChannel;

@interface SGDaemon : NSObject <SGProtocolDelegate>

/**
 * Attaches the process-wide control channel.  The daemon uses it to publish
 * STATE_CHANGED and CONFIG_RELOADED events to any subscriber.  Owned and
 * lifecycle-managed by the caller (main.m); the daemon only retains a
 * reference for the duration it is attached.  Pass nil to detach.
 */
- (void)attachControlChannel:(SGControlChannel *)channel;

/**
 * Attaches the SGControlChannel client used to deliver pushes to the
 * SpringBoard tweak.  When attached, the daemon routes push delivery
 * through this channel instead of the legacy SGMach_SendPushToAppTopic
 * raw Mach path.  Lifecycle-managed by the caller (main.m).
 */
- (void)attachSpringBoardClient:(SGControlChannel *)client;

/**
 * Starts the daemon's connection state machine.
 */
- (void)start;

/**
 * Signals the daemon that network reachability has changed.
 */
- (void)systemNetworkReachabilityDidChangeWithWWANStatus:(BOOL)isWWAN;

/**
 * Signals the daemon that the network has dropped completely.
 */
- (void)systemNetworkDidDrop;

/**
 * Triggers a reload of the configuration and forces a reconnection if needed.
 */
- (void)handleConfigurationReloadRequest;

/**
 * Requests a graceful disconnection and loop termination.
 */
- (void)requestGracefulDisconnect;

/**
 * Called by the IOKit power notification callback when the system has fully
 * woken from deep sleep. Only acts if the FSM is in SGStateIdleCircuitOpen —
 * it is a no-op from all other states, so it is safe to call unconditionally
 * on every wake without wasting battery.
 */
- (void)handleSystemWake;

/**
 * Asks the SpringBoard tweak to reset iOS's view of the bundle's push
 * registration so its next register call hits our hook fresh.
 */
- (void)dispatchResetRegistrationForBundleIdentifier:(NSString *)bundleID
                                          completion:(void (^)(SGControlError err))completion;

/**
 * Atomically removes the given bundle from the plist's pendingDeletions
 * field.  Called at the end of the DELETE_APP cascade once the operational
 * cleanup has completed, so the persistent intent record is cleared in
 * lockstep with the cleanup it represents.  No-op if the field is missing
 * or the bundle isn't in the list.
 */
- (void)clearPendingDeletionForBundleIdentifier:(NSString *)bundleID;

/**
 * Per-bundle operational cleanup: drops the DB row and scrubs queued
 * local pending deliveries.  Idempotent.  Does NOT flush the server filter
 * or clear pendingDeletions.
 */
- (void)_runDeletionCascadeForBundle:(NSString *)bundleID;

/**
 * Atomically deletes a profile slot: keychain entry + plist file + any
 * database rows tied to that profile.  If the deleted slot was active,
 * the daemon also disables itself and disconnects.  Returns YES on full
 * success, NO if any step failed (caller's IPC reply uses this).
 */
- (BOOL)performDeleteProfileAtIndex:(NSInteger)profileIdx;

/**
 * Switches the active profile slot.  Writes activeProfile to the main
 * prefs plist, reloads configuration, and kicks the FSM so an existing
 * connection drops and a fresh connection to the new server's address
 * is attempted immediately.  Returns YES on success; NO if the index
 * is invalid or the target profile has no plist on disk.
 */
- (BOOL)performSetActiveProfileAtIndex:(NSInteger)profileIdx;

/**
 * Atomically creates or edits a profile slot.  The daemon owns the profile
 * plist and per-profile certificate file.  Passing nil/empty certificatePEM
 * preserves the existing certificate for address-only edits.
 */
- (BOOL)performSaveProfileAtIndex:(NSInteger)profileIdx
                    serverAddress:(NSString *)serverAddress
                    certificatePEM:(NSString *)certificatePEM;

@end

#endif
