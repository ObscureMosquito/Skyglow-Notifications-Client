#ifndef SKYGLOW_SG_DAEMON_H
#define SKYGLOW_SG_DAEMON_H

#import <Foundation/Foundation.h>
#import "SGProtocolHandler.h"
#import "SGStatus.h"
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
    SGEventDisconnected,
    SGEventVersionMismatch,
    SGEventBackoffTimerFired,
    SGEventSystemDidWake,
    SGEventAuthTimeout
};

@class SGControlChannel;
@class SGStateStore;

@interface SGDaemon : NSObject <SGProtocolDelegate>

/** The daemon's single writer over persistent app state and missed-uninstall replay */
@property (nonatomic, readonly) SGStateStore *stateStore;

/** Used to publish STATE_CHANGED events to any subscriber */
- (void)attachControlChannel:(SGControlChannel *)channel;

/** Handle to the platform layer, used only for final local notification delivery */
- (void)attachDeliveryPlatform:(id<SGPlatform>)platform;

/** Retry pending local deliveries */
- (void)kickLocalDeliveryDrain;

/** Starts the daemon's connection state machine */
- (void)start;

/** Triggers a reload of the configuration and forces a reconnection if needed. */
- (void)handleConfigurationReloadRequest;

/** Requests a graceful disconnection and loop termination. */
- (BOOL)requestGracefulDisconnect;

/** Atomically deletes a profile slot */
- (BOOL)performDeleteProfileAtIndex:(NSInteger)profileIdx;

/** Switches the active profile slot */
- (BOOL)performSetActiveProfileAtIndex:(NSInteger)profileIdx;

/** Atomically creates or edits a profile slot */
- (BOOL)performSaveProfileAtIndex:(NSInteger)profileIdx
                    serverAddress:(NSString *)serverAddress
                    certificatePEM:(NSString *)certificatePEM;

/** Stores or removes a profile's operator-issued registration identity */
- (BOOL)performSetRegistrationIdentityAtIndex:(NSInteger)profileIdx
                                  identityPEM:(NSString *)identityPEM;

/** Enables the daemon, duh */
- (BOOL)performSetEnabled:(BOOL)enabled;

@end

#endif
