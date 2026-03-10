#ifndef SKYGLOW_SG_DAEMON_H
#define SKYGLOW_SG_DAEMON_H

#import <Foundation/Foundation.h>
#import "SGProtocolHandler.h"
#import "SGStatusServer.h"

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
    
    // Timers
    SGEventBackoffTimerFired
};

/** Darwin Notifications */
#define kSGConfigurationDidUpdateNotification "com.skyglow.sgn.reload_config"

@class SGMachServer;

@interface SGDaemon : NSObject <SGProtocolDelegate>

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

@end

#endif