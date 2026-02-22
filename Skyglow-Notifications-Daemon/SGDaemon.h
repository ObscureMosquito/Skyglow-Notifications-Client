#ifndef SKYGLOW_SG_DAEMON_H
#define SKYGLOW_SG_DAEMON_H

#import <Foundation/Foundation.h>
#import "SGProtocolHandler.h"
#import "SGStatusServer.h"

// --- State Machine Timing Constants ---
#define SG_INITIAL_BACKOFF_SECONDS        2
#define SG_MAX_BACKOFF_SECONDS            600
#define SG_MAX_CONSECUTIVE_FAILURES       12
#define SG_MAX_JITTER_SECONDS             5
#define SG_AUTH_FAILURE_BACKOFF_SECONDS   30
#define SG_CIRCUIT_OPEN_WAIT_SECONDS      300

// --- Darwin Notifications ---
#define kSGConfigurationDidUpdateNotification "com.skyglow.sgn.reload_config"

@interface SGDaemon : NSObject <SGProtocolDelegate>

/**
 * Starts the primary connection and message processing loop.
 * This method blocks and should be called on a background thread.
 */
- (void)runPrimaryConnectionLoop;

/**
 * Signals the daemon that network reachability has changed.
 */
- (void)systemNetworkReachabilityDidChangeWithWWANStatus:(BOOL)isWWAN;

/**
 * Triggers a reload of the configuration and forces a reconnection if needed.
 */
- (void)handleConfigurationReloadRequest;

/**
 * Requests a graceful disconnection and loop termination.
 */
- (void)requestGracefulDisconnect;

// --- FSM Transitions ---

- (void)transitionToState:(SGState)newState;
- (void)transitionToState:(SGState)newState 
           backoffSeconds:(uint32_t)backoff 
                 serverIP:(const char *)ip;

@end

#endif /* SKYGLOW_SG_DAEMON_H */