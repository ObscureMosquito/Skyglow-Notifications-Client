#ifndef SKYGLOW_SG_DAEMON_H
#define SKYGLOW_SG_DAEMON_H

#import <Foundation/Foundation.h>
#import "SGProtocolHandler.h"
#import "SGStatusServer.h"
#import "SGControlChannelProtocol.h"

@protocol SGPlatform;

typedef NS_ENUM(NSInteger, SGEvent) {
    SGEventStartRequested,
    SGEventStopRequested,
    SGEventConfigReloaded,
    SGEventNetworkUp,
    SGEventNetworkDown,
    SGEventDNSResolved,
    SGEventDNSFailed,
    SGEventConnectSuccess,
    SGEventConnectFailed,
    SGEventAuthSuccess,
    SGEventAuthFailed,
    SGEventRegistrationRejected,
    SGEventReplaced,
    SGEventDisconnected,
    SGEventVersionMismatch,
    SGEventBackoffTimerFired,
    SGEventSystemDidWake,
    SGEventAuthTimeout
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

/* The daemon's handle to the platform layer, used only for final local
 * notification delivery. Pass nil before stopping the platform. */
- (void)attachDeliveryPlatform:(id<SGPlatform>)platform;

/* Retry pending local deliveries — called when the iOS presentation channel
 * (re)connects. No-op if there is nothing pending. */
- (void)kickLocalDeliveryDrain;

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
/**
 * Sends a normal disconnect frame, then stops and drains transport workers.
 * Returns YES when no connection existed or the frame was written before the
 * bounded shutdown deadline.
 */
- (BOOL)requestGracefulDisconnect;

/**
 * Called by the IOKit power notification callback when the system has fully
 * woken from deep sleep. Safe to call in every state; connected sessions probe
 * liveness and backoff/legacy-circuit states retry immediately.
 */
- (void)handleSystemWake;

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
