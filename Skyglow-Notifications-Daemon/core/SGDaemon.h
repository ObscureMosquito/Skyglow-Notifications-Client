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
@class SGStateStore;

@interface SGDaemon : NSObject <SGProtocolDelegate>

/**
 * The daemon's single-writer authority over persistent app state and
 * missed-uninstall replay.  IPC handlers route every app-state mutation through
 * this; the daemon itself uses it for the writes behind its config commands.
 */
@property (nonatomic, readonly) SGStateStore *stateStore;

/**
 * Attaches the process-wide control channel.  The daemon uses it to publish
 * STATE_CHANGED events to any subscriber.  Owned and
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

/* Exposed so the daemon's IPC entry points can proxy prefs-bundle requests
 * to SpringBoard.  Prefs no longer holds its own SB channel, its only
 * persistent connection is to the daemon, which always stays warm. */
- (SGControlChannel *)springBoardClient;

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

/**
 * Flips the global "enabled" switch.  The daemon owns the write of the
 * `enabled` key in main prefs (making it the sole writer of the keys it
 * consumes), then reloads configuration and drives the FSM enable/disable
 * cascade.  Returns YES if the plist was written.
 */
- (BOOL)performSetEnabled:(BOOL)enabled;

@end

#endif
