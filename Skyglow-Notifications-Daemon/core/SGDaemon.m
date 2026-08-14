#import "SGDaemon.h"
#import "SGConnectionPolicy.h"
#import "SGNotificationProcessor.h"
#import "SGConfiguration.h"
#import "SGDatabaseManager.h"
#import "SGTokenManager.h"
#import "SGProtocolHandler.h"
#import "SGKeepAliveOffload.h"
#import "SGServerLocator.h"
#import "SGCryptoEngine.h"
#import "SGAvailability.h"
#import "SGControlChannel.h"
#import "SGReachabilityMonitor.h"
#import "SGStateStore.h"
#import "SGLog.h"
#import "SGPlatform.h"
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdatomic.h>
#include <libkern/OSAtomic.h>
#include <errno.h>

static const int64_t kSGGracefulDisconnectTimeoutSec = 2;

_Static_assert(SG_POWER_ASSERTION_TIMEOUT_SEC >= SGP_PONG_TIMEOUT_SEC + 10,
               "power-assertion backstop must outlast the probe liveness check");

typedef struct { SGState state; SGEvent onTimeout; uint32_t seconds; } SGStateDeadline;

static const SGStateDeadline kSGStateDeadlines[] = {
    { SGStateResolvingDNS,   SGEventDNSFailed,     SGP_NET_OP_TIMEOUT_SEC + 5 },
    { SGStateConnecting,     SGEventConnectFailed, SGP_NET_OP_TIMEOUT_SEC + 5 },
    { SGStateAuthenticating, SGEventAuthTimeout,   SGP_NET_OP_TIMEOUT_SEC * 2 },
    { SGStateRegistering,    SGEventDisconnected,  SGP_NET_OP_TIMEOUT_SEC * 2 },
};

static BOOL isValidPort(NSString *port) {
    const char *utf8 = [port UTF8String];
    return utf8 && SG_PortCStringIsValid(utf8, strlen(utf8));
}

@interface SGDaemon ()
- (SGControlError)_deliverPushTopic:(NSString *)topic
                           payload:(NSDictionary *)payload;
- (void)systemNetworkReachabilityDidChangeWithWWANStatus:(BOOL)isWWAN;
- (void)systemNetworkDidDrop;
- (void)handleSystemWake;
@end

@implementation SGDaemon {
    NSLock                *_stateLock;
    int                    _consecutiveFailures;
    id                     _growthAlgorithm;
    SGNotificationProcessor *_notificationProcessor;
    BOOL                   _activeModeEntered;
    uint32_t               _fsmGeneration;
    dispatch_queue_t       _entryActionQueue;
    dispatch_queue_t       _connectionQueue;
    dispatch_queue_t       _protocolWorkerQueue;
    id                     _keepAliveTimer;
    BOOL                   _isWiFi;
    char                   _lastErrorDetail[128];
    SGStateStore          *_stateStore;
    SGControlChannel      *_controlChannel;
    id<SGPlatform>         _deliveryPlatform;
    SGReachabilityMonitor *_reachability;
    _Atomic uint32_t       _probeAssertionID;
    _Atomic bool           _probeInFlight;
}

- (id)init {
    if ((self = [super init])) {
        _stateLock           = [[NSLock alloc] init];
        _consecutiveFailures = 0;
        _fsmGeneration       = 0;
        _entryActionQueue    = dispatch_queue_create("com.skyglow.daemon.entry", DISPATCH_QUEUE_SERIAL);
        _connectionQueue     = dispatch_queue_create("com.skyglow.daemon.connect", DISPATCH_QUEUE_SERIAL);
        _protocolWorkerQueue = dispatch_queue_create("com.skyglow.daemon.protocol", DISPATCH_QUEUE_SERIAL);
        _stateStore = [[SGStateStore alloc] init];
        __unsafe_unretained SGDaemon *daemonSelf = self;
        _notificationProcessor = [[SGNotificationProcessor alloc]
            initWithDeliveryHandler:^SGControlError(NSString *bundleID,
                                                    NSDictionary *payload) {
                return [daemonSelf _deliverPushTopic:bundleID payload:payload];
            }];
    }
    return self;
}

- (void)dealloc {
    [_notificationProcessor suspendPendingDeliveryRetries];
    [_notificationProcessor release];
    [_stateLock release];
    [_growthAlgorithm release];
    [_controlChannel release];
    [_deliveryPlatform release];
    [_reachability stopMonitoringSystemNetworkChanges];
    [_reachability release];
    [[SGAvailability shared] stopPowerEventMonitoring];
    if (_keepAliveTimer) { [_keepAliveTimer invalidate]; [_keepAliveTimer release]; }
    dispatch_release(_entryActionQueue);
    dispatch_release(_connectionQueue);
    dispatch_release(_protocolWorkerQueue);
    [_stateStore release];
    [super dealloc];
}

- (uint32_t)_captureGeneration {
    [_stateLock lock];
    uint32_t generation = _fsmGeneration;
    [_stateLock unlock];
    return generation;
}

- (BOOL)_generationIsStale:(uint32_t)generation {
    [_stateLock lock];
    BOOL stale = (_fsmGeneration != generation);
    [_stateLock unlock];
    return stale;
}

- (SGStateStore *)stateStore {
    return _stateStore;
}

- (void)attachControlChannel:(SGControlChannel *)channel {
    if (channel == _controlChannel) return;
    [channel retain];
    [_controlChannel release];
    _controlChannel = channel;
}

- (void)attachDeliveryPlatform:(id<SGPlatform>)platform {
    if (platform == _deliveryPlatform) return;
    [platform retain];
    [_deliveryPlatform release];
    _deliveryPlatform = platform;
}

- (void)kickLocalDeliveryDrain {
    [_notificationProcessor kickPendingDeliveryDrain];
}

- (void)start {
    [self _startReachabilityMonitor];
    [self reconcileTokensWithPlist];
    [self handleEvent:SGEventStartRequested payload:nil];
}

#pragma mark - Active / Disabled Mode Lifecycle

- (void)_enterActiveMode {
    [self reconcileTokensWithPlist];

    [_stateLock lock];
    if (!_growthAlgorithm) {

        _isWiFi = YES;
        double savedInterval = [[SGDatabaseManager sharedManager] loadKeepAliveIntervalForWiFi:YES];
        _growthAlgorithm = [[SGAvailability shared]
            reinitializeGrowthAlgorithmForWiFi:YES
                                 savedInterval:savedInterval];
    }
    [_stateLock unlock];

    [_notificationProcessor kickPendingDeliveryDrain];
    __unsafe_unretained SGDaemon *daemonSelf = self;
    [[SGAvailability shared]
        startPowerEventMonitoringWithWakeHandler:^{
            [daemonSelf handleSystemWake];
        }
        willSleepHandler:^{
            [daemonSelf _armScheduledWakeIfNeeded];
        }];
}

- (void)_exitActiveMode {
    [_stateLock lock];
    if (_growthAlgorithm) {
        [_growthAlgorithm release];
        _growthAlgorithm = nil;
    }
    [_stateLock unlock];

    [self _invalidateKeepAliveTimer];
    [[SGAvailability shared] cancelPendingScheduledWake];
    [_notificationProcessor suspendPendingDeliveryRetries];
    [[SGAvailability shared] stopPowerEventMonitoring];
}

- (void)_startReachabilityMonitor {
    if (_reachability) return;
    __unsafe_unretained SGDaemon *daemonSelf = self;
    _reachability = [[SGReachabilityMonitor alloc] initWithChangeHandler:^(BOOL isReachable, BOOL isWWAN) {
        if (isReachable) {
            [daemonSelf systemNetworkReachabilityDidChangeWithWWANStatus:isWWAN];
        } else {
            [daemonSelf systemNetworkDidDrop];
        }
    }];
    [_reachability startMonitoringSystemNetworkChanges];
}

- (bool)_isNetworkPathViable {
    return _reachability ? [_reachability isReachable] : true;
}

- (void)reconcileTokensWithPlist {
    NSDictionary *appStatus = [_stateStore appStatusDictionary];
    SGDatabaseManager *db = [SGDatabaseManager sharedManager];

    NSMutableSet *plistYes = [NSMutableSet set];
    NSMutableSet *plistNo  = [NSMutableSet set];
    for (NSString *bundleID in appStatus) {
        if ([[appStatus objectForKey:bundleID] boolValue]) {
            [plistYes addObject:bundleID];
        } else {
            [plistNo addObject:bundleID];
        }
    }

    NSSet *dbBundles = [db registeredBundleIdentifiers];

    for (NSString *bundleID in dbBundles) {
        if ([plistYes containsObject:bundleID]) {
            [db setMuted:NO  forBundleIdentifier:bundleID];
        } else if ([plistNo containsObject:bundleID]) {
            [db setMuted:YES forBundleIdentifier:bundleID];
        }
    }

    NSString *serverAddr = [[SGConfiguration sharedConfiguration] serverAddress];
    BOOL mutated = NO;
    if (serverAddr && [serverAddr length] > 0) {
        SGTokenManager *tokenMgr = [[SGTokenManager alloc] init];
        NSMutableSet *allOptedIn = [NSMutableSet setWithSet:plistYes];
        [allOptedIn unionSet:plistNo];
        for (NSString *bundleID in allOptedIn) {
            if (![dbBundles containsObject:bundleID]) {
                NSError *err = nil;
                NSData *token = [tokenMgr synchronizedTokenForBundleIdentifier:bundleID error:&err];
                if (token) {
                    SGLOGI(SGDaemon, "code=%s bundle=%s result=generated", SGND_TOKEN_MISSING_GENERATED, [bundleID UTF8String]);
                    if ([plistNo containsObject:bundleID]) {
                        [db setMuted:YES forBundleIdentifier:bundleID];
                    }
                    mutated = YES;
                } else {
                    SGLOGE(SGDaemon, "code=%s bundle=%s result=failed reason=%s", SGND_TOKEN_GENERATE_FAILED,
                                [bundleID UTF8String], [[err description] UTF8String]);
                }
            }
        }
        [tokenMgr release];
    } else {
        NSMutableSet *allOptedIn = [NSMutableSet setWithSet:plistYes];
        [allOptedIn unionSet:plistNo];
        for (NSString *bundleID in allOptedIn) {
            if (![dbBundles containsObject:bundleID]) {
                SGLOGI(SGDaemon, "code=%s bundle=%s action=defer_until_registration", SGND_TOKEN_DEFER_UNREGISTERED, [bundleID UTF8String]);
            }
        }
    }
    if (mutated) {
        SGP_FlushActiveTopicFilter();
    }
}

- (void)handleEvent:(SGEvent)event payload:(id)payload {
    [_stateLock lock];
    
    SGStatusPayload currentStatus;
    SGStatusServer_Current(&currentStatus);
    SGState currentState = (SGState)currentStatus.state;
    
    SGLOGD(SGDaemon, "code=%s event=%ld state=%s", SGND_FSM_EVENT, (long)event, SGState_GetName(currentState));

    if (event == SGEventStopRequested) {
        _consecutiveFailures = 0;
        strlcpy(_lastErrorDetail, "Daemon is disabled", sizeof(_lastErrorDetail));
        [self executeTransitionToState:SGStateDisabled backoff:0 ip:NULL];
        [_stateLock unlock];
        return;
    }

    if (event == SGEventStartRequested || event == SGEventConfigReloaded) {
        SGConfiguration *config = [SGConfiguration sharedConfiguration];
        SGState target = SGConnectionStateForConfiguration(
            [config isEnabled], [config hasProfile], [config isValid],
            [self _isNetworkPathViable]);

        _consecutiveFailures = 0;
        switch (target) {
            case SGStateDisabled:
                strlcpy(_lastErrorDetail, "Daemon is disabled", sizeof(_lastErrorDetail));
                break;
            case SGStateIdleUnregistered:
                strlcpy(_lastErrorDetail, "No profile configured", sizeof(_lastErrorDetail));
                break;
            case SGStateErrorBadConfig:
                strlcpy(_lastErrorDetail, "Missing server address or certificate", sizeof(_lastErrorDetail));
                break;
            case SGStateIdleNoNetwork:
                strlcpy(_lastErrorDetail, "No network connection available", sizeof(_lastErrorDetail));
                break;
            default:
                _lastErrorDetail[0] = '\0';
                break;
        }

        [self executeTransitionToState:target backoff:0 ip:NULL];
        [_stateLock unlock];
        return;
    }

    if (event == SGEventNetworkDown) {
        if (currentState != SGStateDisabled &&
            currentState != SGStateIdleUnregistered &&
            currentState != SGStateErrorBadConfig &&
            currentState != SGStateErrorVersionMismatch &&
            currentState != SGStateErrorAuth) {
            strlcpy(_lastErrorDetail, "No network connection available", sizeof(_lastErrorDetail));
            [self executeTransitionToState:SGStateIdleNoNetwork backoff:0 ip:NULL];
        }
        [_stateLock unlock];
        return;
    }

    if (event == SGEventVersionMismatch) {
        _consecutiveFailures = 0;
        strlcpy(_lastErrorDetail,
                "Server rejected client: protocol version mismatch. Update Skyglow.",
                sizeof(_lastErrorDetail));
        [self executeTransitionToState:SGStateErrorVersionMismatch backoff:0 ip:NULL];
        [_stateLock unlock];
        return;
    }

    uint32_t genBeforeDispatch = _fsmGeneration;
    BOOL handledWithoutTransition = NO;

    switch (currentState) {
        case SGStateStarting:
        case SGStateDisabled:
        case SGStateErrorBadConfig:
        case SGStateErrorVersionMismatch:
        case SGStateIdleUnregistered:
            break;

        case SGStateIdleNoNetwork:
            if (event == SGEventNetworkUp || event == SGEventSystemDidWake) {
                _consecutiveFailures = 0;
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            }
            break;

        case SGStateResolvingDNS:
            if (event == SGEventDNSResolved) {
                NSDictionary *txt = (NSDictionary *)payload;
                [[SGConfiguration sharedConfiguration] setServerIPAddress:txt[@"tcp_addr"]];
                [[SGConfiguration sharedConfiguration] setServerPort:txt[@"tcp_port"]];
                [self executeTransitionToState:SGStateConnecting backoff:0 ip:[txt[@"tcp_addr"] UTF8String]];
            } else if (event == SGEventDNSFailed) {
                strlcpy(_lastErrorDetail, "DNS resolution failed", sizeof(_lastErrorDetail));
                [self executeFailureRecovery:SGFailureClassDNS];
            }
            break;

        case SGStateBackingOff:
            if (event == SGEventBackoffTimerFired || event == SGEventNetworkUp) {
                if (event == SGEventNetworkUp) _consecutiveFailures = 0;
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            } else if (event == SGEventSystemDidWake) {
                SGLOGI(SGDaemon, "code=%s state=BackingOff action=retry_now", SGND_WAKE_BACKOFF_RESET);
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            }
            break;

        case SGStateConnecting:
            if (event == SGEventConnectSuccess) {
                [self executeTransitionToState:SGStateAuthenticating backoff:0 ip:NULL];
            } else if (event == SGEventConnectFailed || event == SGEventDisconnected) {
                strlcpy(_lastErrorDetail, "Connection to server failed", sizeof(_lastErrorDetail));
                SGFailureClass cls = [payload isKindOfClass:[NSNumber class]]
                    ? (SGFailureClass)[(NSNumber *)payload intValue]
                    : SGFailureClassTransport;
                [self executeFailureRecovery:cls];
            }
            break;

        case SGStateRegistering:
            if (event == SGEventAuthFailed) {
                strlcpy(_lastErrorDetail, "Registration succeeded but key could not be stored", sizeof(_lastErrorDetail));
                [self executeFailureRecovery:SGFailureClassTransport];
            } else if (event == SGEventRegistrationRejected) {
                NSDictionary *info = [payload isKindOfClass:[NSDictionary class]] ? (NSDictionary *)payload : nil;
                NSString *reason = [info objectForKey:@"reason"];
                uint8_t code = (uint8_t)[[info objectForKey:@"code"] unsignedCharValue];
                snprintf(_lastErrorDetail, sizeof(_lastErrorDetail),
                         "Registration Failed: %s",
                         reason ? [reason UTF8String] : "unknown reason");
                if (code == 0x05) {
                    [self executeTransitionToState:SGStateErrorAuth backoff:0 ip:NULL];
                } else {
                    [self executeFailureRecovery:SGFailureClassTransport];
                }
            } else if (event == SGEventDisconnected) {
                strlcpy(_lastErrorDetail, "Disconnected during registration", sizeof(_lastErrorDetail));
                [self executeFailureRecovery:SGFailureClassTransport];
            }
            break;

        case SGStateAuthenticating:
            if (event == SGEventAuthSuccess) {
                _consecutiveFailures = 0;
                _lastErrorDetail[0] = '\0';
                [self executeTransitionToState:SGStateConnected backoff:0 ip:NULL];
            } else if (event == SGEventAuthFailed) {
                strlcpy(_lastErrorDetail, "Server rejected authentication, credentials may be revoked; re-register to recover", sizeof(_lastErrorDetail));
                [self executeTransitionToState:SGStateErrorAuth backoff:0 ip:NULL];
            } else if (event == SGEventAuthTimeout) {
                strlcpy(_lastErrorDetail, "Authentication timed out (30s)", sizeof(_lastErrorDetail));
                [self executeFailureRecovery:SGFailureClassTransport];
            } else if (event == SGEventDisconnected) {
                strlcpy(_lastErrorDetail, "Disconnected during authentication", sizeof(_lastErrorDetail));
                [self executeFailureRecovery:SGFailureClassTransport];
            }
            break;

        case SGStateConnected:
            if (event == SGEventDisconnected) {
                strlcpy(_lastErrorDetail, "Connection lost", sizeof(_lastErrorDetail));
                [self executeFailureRecovery:SGFailureClassTransport];
            } else if (event == SGEventAuthFailed) {

                strlcpy(_lastErrorDetail, "Server revoked authentication, re-register to recover", sizeof(_lastErrorDetail));
                [self executeTransitionToState:SGStateErrorAuth backoff:0 ip:NULL];
            } else if (event == SGEventSystemDidWake || event == SGEventNetworkUp) {
                SGLOGI(SGDaemon, "code=%s trigger=%s action=probe_liveness", SGND_KEEPALIVE_PROBE,
                       (event == SGEventSystemDidWake) ? "system_wake" : "network_change");
                [self _probeConnectionLiveness];
                handledWithoutTransition = YES;
            }
            break;
            
        case SGStateErrorAuth:
            break;

        case SGStateIdleCircuitOpen:
            if (event == SGEventNetworkUp) {
                _consecutiveFailures = 0;
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            } else if (event == SGEventSystemDidWake) {
                SGLOGI(SGDaemon, "code=%s state=IdleCircuitOpen action=reset_failures", SGND_WAKE_CIRCUIT_RESET);
                _consecutiveFailures = 0;
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            } else if (event == SGEventBackoffTimerFired) {
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            }
            break;

        default:
            break;
    }

    if (_fsmGeneration == genBeforeDispatch && !handledWithoutTransition) {
        SGLOGW(SGDaemon, "code=%s state=%s event=%ld result=no_transition",
               SGND_FSM_UNHANDLED_EVENT, SGState_GetName(currentState), (long)event);
    }

    [_stateLock unlock];
}

- (void)executeTransitionToState:(SGState)newState backoff:(uint32_t)backoff ip:(const char *)ip {
    SGStatusPayload current;
    SGStatusServer_Current(&current);
    if (!SGConnectionTransitionIsLegal((SGState)current.state, newState)) {
        SGLOGE(SGDaemon, "code=%s from=%s to=%s result=rejected", SGND_FSM_TRANSITION_INVALID,
                    SGState_GetName((SGState)current.state), SGState_GetName(newState));
        return;
    }

    _fsmGeneration++;
    uint32_t capturedGen = _fsmGeneration;

    NSString *currentIPStr = [[SGConfiguration sharedConfiguration] serverIPAddress];
    const char *resolvedIP = ip ? ip : (currentIPStr ? [currentIPStr UTF8String] : NULL);

    if (newState == SGStateConnected || newState == SGStateResolvingDNS ||
        newState == SGStateConnecting || newState == SGStateAuthenticating ||
        newState == SGStateRegistering) {
        _lastErrorDetail[0] = '\0';
    }

    SGConfiguration *config = [SGConfiguration sharedConfiguration];
    uint32_t activeProfile = [config hasProfile] ? (uint32_t)[config activeProfileIndex] : 0;
    SGStatusServer_Post(newState, (uint32_t)_consecutiveFailures, backoff,
                        resolvedIP, _lastErrorDetail, activeProfile);
    SGLOGD(SGDaemon, "code=%s to=%s generation=%u", SGND_FSM_TRANSITION, SGState_GetName(newState), capturedGen);

    if (_controlChannel) {
        /* Snapshot under the lock so the payload reflects this transition, but
         * publish off the lock: postEvent can fan out to subscribers and we must
         * never run their callbacks while holding _stateLock (re-entry would
         * deadlock).  The serial entry-action queue preserves STATE_CHANGED
         * ordering and runs the entry action for this state right after. */
        SGStatusPayload snapshot;
        SGStatusServer_Current(&snapshot);
        NSData *payload = [NSData dataWithBytes:&snapshot length:sizeof(snapshot)];
        SGControlChannel *channel = _controlChannel;
        dispatch_async(_entryActionQueue, ^{
            [channel postEvent:SGCEVT_STATE_CHANGED payload:payload];
        });
    }

    BOOL needsActiveServices = SGConnectionStateNeedsActiveServices(newState);

    dispatch_async(_entryActionQueue, ^{
        if ([self _generationIsStale:capturedGen]) return;

        [self _invalidateKeepAliveTimer];

        /* Track actual service lifetime on this serial queue. A prior state's
         * stale entry action may never have run, so status-to-status deltas are
         * not sufficient to decide whether setup is still needed. */
        if (needsActiveServices && !self->_activeModeEntered) {
            self->_activeModeEntered = YES;
            [self _enterActiveMode];
        }

        switch (newState) {
            case SGStateResolvingDNS: {
                SGP_AbortConnection();
                NSString *addr = [[SGConfiguration sharedConfiguration] deviceAddress];
                if (!addr || addr.length == 0) {
                    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                        SGP_PrepareRegistrationKeypair();
                    });
                }
                [self performDNSResolution];
                break;
            }
            case SGStateConnecting:
                [self performSocketConnection];
                break;
            case SGStateAuthenticating:
                [self startConnectionScopedWorker];
                break;
            case SGStateConnected:
                [self _scheduleKeepAliveTimer];
                break;
            case SGStateBackingOff:
                SGP_AbortConnection();
                [self scheduleTimerForEvent:SGEventBackoffTimerFired
                                      delay:backoff
                              leewayPercent:SG_RETRY_LEEWAY_PERCENT
                                 generation:capturedGen];
                break;
            case SGStateIdleCircuitOpen:
                SGP_AbortConnection();
                if (backoff > 0) {
                    [self scheduleTimerForEvent:SGEventBackoffTimerFired
                                          delay:backoff
                                  leewayPercent:SG_CIRCUIT_LEEWAY_PERCENT
                                     generation:capturedGen];
                }
                break;
            case SGStateDisabled:
            case SGStateIdleUnregistered:
            case SGStateIdleNoNetwork:
            case SGStateErrorBadConfig:
            case SGStateErrorVersionMismatch:
            case SGStateErrorAuth:
                SGP_AbortConnection();
                break;
            default:
                break;
        }

        if (!needsActiveServices && self->_activeModeEntered) {
            self->_activeModeEntered = NO;
            [self _exitActiveMode];
        }
    });

    [self armWatchdogForState:newState generation:capturedGen];
}

- (void)armWatchdogForState:(SGState)state generation:(uint32_t)generation {
    for (size_t i = 0; i < sizeof(kSGStateDeadlines) / sizeof(kSGStateDeadlines[0]); i++) {
        if (kSGStateDeadlines[i].state == state) {
            [self scheduleTimerForEvent:kSGStateDeadlines[i].onTimeout
                                  delay:kSGStateDeadlines[i].seconds
                          leewayPercent:0
                             generation:generation];
            return;
        }
    }
}

- (void)executeFailureRecovery:(SGFailureClass)failureClass {
    uint32_t jitter = arc4random_uniform(SG_MAX_JITTER_SECONDS + 1);
    uint32_t serverHint = SGP_GetLastDisconnectRetryAfter();
    SGConnectionRecovery recovery = SGConnectionRecoveryForFailure(
        failureClass, (unsigned int)_consecutiveFailures + 1,
        [self _isNetworkPathViable], jitter, serverHint);
    if (recovery.countsAsFailure) _consecutiveFailures++;

    if (recovery.state == SGStateIdleNoNetwork) {
        strlcpy(_lastErrorDetail, "No network connection available", sizeof(_lastErrorDetail));
        [self executeTransitionToState:SGStateIdleNoNetwork backoff:0 ip:NULL];
        return;
    }

    if (recovery.state == SGStateBackingOff) {
        if (serverHint > recovery.delaySeconds) {
            SGLOGW(SGDaemon, "code=%s retry_after=%u capped=%u action=cap_for_liveness",
                   SGND_BACKOFF_RETRY_AFTER, serverHint, recovery.delaySeconds);
        } else if (serverHint > 0) {
            SGLOGI(SGDaemon, "code=%s retry_after=%u action=honor",
                   SGND_BACKOFF_RETRY_AFTER, serverHint);
        }
        SGLOGI(SGDaemon, "code=%s delay=%u failure=%d action=retry",
               SGND_BACKOFF_SCHEDULED, recovery.delaySeconds, _consecutiveFailures);
    } else {
        SGLOGW(SGDaemon, "code=%s failure=%d floor=%u action=wait_for_signal_or_floor",
               SGND_CIRCUIT_TRIPPED, _consecutiveFailures, recovery.delaySeconds);
    }
    [self executeTransitionToState:recovery.state backoff:recovery.delaySeconds ip:NULL];
}

- (void)protocolDidReceiveWelcomeChallenge {
    NSString *clientAddress = [[SGConfiguration sharedConfiguration] deviceAddress];

    if (!clientAddress || [clientAddress length] == 0) {
        [_stateLock lock];
        [self executeTransitionToState:SGStateRegistering backoff:0 ip:NULL];
        [_stateLock unlock];
        
        if (!SGP_BeginFirstTimeRegistration()) {
            [self handleEvent:SGEventDisconnected payload:nil];
        }
        return;
    }

    RSA *privKey = SG_CryptoGetClientPrivateKey();
    if (!privKey) {
        SGLOGW(SGDaemon, "code=%s reason=missing_or_invalid_private_key action=wipe_profile", SGND_REGISTRATION_PROFILE_INVALID);
        [self handleEvent:SGEventAuthFailed payload:nil];
        return;
    }

    SGP_BeginLoginHandshake(clientAddress, privKey);
}

- (void)protocolDidAuthenticateSuccessfully {
    [self handleEvent:SGEventAuthSuccess payload:nil];

    NSString *currentAddr = [[SGConfiguration sharedConfiguration] serverAddress];
    if (currentAddr) {
        [SGServerLocator refreshDNSCacheAsynchronouslyForAddress:currentAddr];
    }

    SGP_FlushPendingAcknowledgements();
    SGP_FlushActiveTopicFilter();
    SGP_RequestOfflineMessages();
    [[SGDatabaseManager sharedManager] checkpoint];
    [[SGDatabaseManager sharedManager] pruneExpiredSeenMessagesAsOf:(int64_t)time(NULL)];

    [self _attemptKeepAliveOffload];
    [_notificationProcessor kickPendingDeliveryDrain];
}

- (void)_attemptKeepAliveOffload {
    [_stateLock lock];
    double interval = [self _currentKeepAliveInterval];
    [_stateLock unlock];
    SGKAOffload_TryEnable(interval);
}

- (void)protocolDidReceiveNotification:(NSDictionary *)messageDict {
    [_notificationProcessor processNotification:messageDict];
}


- (void)protocolDidReceiveKeepAlivePong {
    [self _releaseProbeAssertion:atomic_load(&_probeAssertionID)];

    [_stateLock lock];
    double oldVal = [self _currentKeepAliveInterval];
    [self _processKeepAliveResult:YES];
    double newVal = [self _currentKeepAliveInterval];
    BOOL isWiFi = _isWiFi;
    [_stateLock unlock];
    
    if (newVal != oldVal) {
        [[SGDatabaseManager sharedManager] saveKeepAliveInterval:newVal forWiFi:isWiFi];
    }

    [self _scheduleKeepAliveTimer];
    SGP_RequestOfflineMessages();
}

- (void)protocolDidFinishOfflineQueueDrain {
    SGLOGI(SGDaemon, "code=%s result=drained", SGND_REGISTRATION_OFFLINE_DONE);
}

- (void)protocolDidReceiveTimeSyncWithOffset:(int64_t)offsetSeconds {
    if (llabs(offsetSeconds) > 60) {
        SGLOGW(SGDaemon, "code=%s offset=%llds result=detected", SGND_REGISTRATION_CLOCK_DRIFT, offsetSeconds);
    }
}

- (void)protocolDidFailRegistrationWithCode:(uint8_t)code reason:(NSString *)reason {
    const char *reasonUTF8 = [reason UTF8String];
    SGLOGE(SGDaemon, "code=%s server_code=%u reason=%s action=backoff",
           SGND_REGISTRATION_SERVER_REJECTED, (unsigned)code, reasonUTF8 ? reasonUTF8 : "unknown");

    [_stateStore setLastRegistrationFailureCode:code
                                        atIndex:[[SGConfiguration sharedConfiguration] activeProfileIndex]];
    NSDictionary *info = [NSDictionary dictionaryWithObjectsAndKeys:
        [NSNumber numberWithUnsignedChar:code], @"code",
        reason ?: @"Unknown", @"reason", nil];
    [self handleEvent:SGEventRegistrationRejected payload:info];
}

- (void)protocolDidCompleteRegistrationWithAddress:(NSString *)deviceAddress privateKey:(char *)pemKey serverVersion:(uint32_t)serverVersion {

    if (!pemKey) {
        [self handleEvent:SGEventDisconnected payload:nil];
        return;
    }

    size_t pemLen = strlen(pemKey);

    NSInteger profileIdx = [[SGConfiguration sharedConfiguration] activeProfileIndex];

    NSMutableData *pemData = [[NSMutableData alloc] initWithBytes:pemKey length:pemLen];
    SGP_ZeroAndFreeKeyMaterial(pemKey, pemLen);
    pemKey = NULL;

    BOOL committed = [_stateStore commitRegistrationForProfileAtIndex:profileIdx
                                                        deviceAddress:deviceAddress
                                                        privateKeyPEM:pemData];
    SG_CryptoWipeData(pemData);
    [pemData release];

    if (!committed) {
        [self handleEvent:SGEventDisconnected payload:nil];
        return;
    }

    SGP_SetRegistrationIdentity(nil);

    [[SGConfiguration sharedConfiguration] reloadFromDisk];

    [self reconcileTokensWithPlist];

    RSA *privKey = SG_CryptoGetClientPrivateKey();
    if (!privKey) {
        SGLOGE(SGDaemon, "code=%s profile=%ld action=wipe_profile", SGND_REGISTRATION_KEY_RELOAD_FAILED, (long)profileIdx);
        [_stateStore wipeProfileCredentialsAtIndex:profileIdx];
        [[SGConfiguration sharedConfiguration] reloadFromDisk];
        [self handleEvent:SGEventAuthFailed payload:nil];
        return;
    }

    [_stateLock lock];
    [self executeTransitionToState:SGStateAuthenticating backoff:0 ip:NULL];
    [_stateLock unlock];
    SGP_BeginLoginHandshake(deviceAddress, privKey);
}

- (void)systemNetworkReachabilityDidChangeWithWWANStatus:(BOOL)isWWAN {
    [_stateLock lock];
    _isWiFi = !isWWAN;
    double savedInterval = [[SGDatabaseManager sharedManager] loadKeepAliveIntervalForWiFi:_isWiFi];
    [self _reinitializeKeepAliveForWiFi:_isWiFi savedInterval:savedInterval];
    [_stateLock unlock];

    [self handleEvent:SGEventNetworkUp payload:nil];
}

- (void)systemNetworkDidDrop {
    [self handleEvent:SGEventNetworkDown payload:nil];
}

- (BOOL)requestGracefulDisconnect {
    BOOL wasConnected = SGP_IsConnected();
    __block BOOL frameSent = NO;
    BOOL sendFinished = !wasConnected;

    if (wasConnected) {
        dispatch_semaphore_t finished = dispatch_semaphore_create(0);
        dispatch_retain(finished);
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            frameSent = SGP_SendClientDisconnect();
            dispatch_semaphore_signal(finished);
            dispatch_release(finished);
        });

        sendFinished = (dispatch_semaphore_wait(
            finished,
            dispatch_time(DISPATCH_TIME_NOW,
                          kSGGracefulDisconnectTimeoutSec * NSEC_PER_SEC)) == 0);
        if (!sendFinished) {
            SGLOGW(SGDaemon, "code=%s result=timeout action=abort", SGND_DAEMON_DISCONNECT_TIMEOUT);
            SGP_AbortConnection();
            sendFinished = (dispatch_semaphore_wait(
                finished,
                dispatch_time(DISPATCH_TIME_NOW,
                              kSGGracefulDisconnectTimeoutSec * NSEC_PER_SEC)) == 0);
        }
        dispatch_release(finished);
    }

    [self handleEvent:SGEventStopRequested payload:nil];

    dispatch_sync(_entryActionQueue, ^{});
    SGP_AbortConnection();
    dispatch_sync(_connectionQueue, ^{});
    dispatch_sync(_protocolWorkerQueue, ^{});
    if (sendFinished) SGP_DisconnectFromServer();

    BOOL graceful = !wasConnected || (sendFinished && frameSent);
    SGLOGI(SGDaemon, "code=%s connected=%s frame=%s result=%s",
           SGND_DAEMON_DISCONNECT_COMPLETE,
           wasConnected ? "yes" : "no",
           frameSent ? "sent" : "not_sent",
           graceful ? "graceful" : "forced");
    return graceful;
}

- (void)handleConfigurationReloadRequest {
    [[SGConfiguration sharedConfiguration] reloadFromDisk];
    [self reconcileTokensWithPlist];
    [self handleEvent:SGEventConfigReloaded payload:nil];
    [_stateStore drainDurableEventInbox];
}

- (void)handleSystemWake {
    if ([SGAvailability shared].scheduledWakeAvailable) {
        SGLOGI(SGDaemon, "code=%s result=woke", SGND_SCHEDULED_WAKE_FIRED);
    }
    [self handleEvent:SGEventSystemDidWake payload:nil];
}

- (void)_armScheduledWakeIfNeeded {
    SGAvailability *avail = [SGAvailability shared];
    if (!avail.scheduledWakeAvailable) return;

    if (SGKAOffload_IsActive()) {
        SGLOGI(SGDaemon, "code=%s action=skip_rtc_wake_offload_active", SGND_KEEPALIVE_OFFLOAD_SUPPRESS_WAKE);
        [avail cancelPendingScheduledWake];
        return;
    }

    if (!SGP_IsConnected()) {
        [avail cancelPendingScheduledWake];
        return;
    }

    [_stateLock lock];
    double interval = [self _currentKeepAliveInterval];
    [_stateLock unlock];

    [avail scheduleWakeAfterInterval:interval];
}

- (BOOL)performSetEnabled:(BOOL)enabled {
    BOOL persisted = [_stateStore updateMainPreferences:^(NSMutableDictionary *preferences) {
        [preferences setObject:[NSNumber numberWithBool:enabled]
                        forKey:@"enabled"];
    }];
    if (!persisted) return NO;

    [self handleConfigurationReloadRequest];
    return YES;
}

- (BOOL)performSaveProfileAtIndex:(NSInteger)profileIdx
                    serverAddress:(NSString *)serverAddress
                    certificatePEM:(NSString *)certificatePEM {
    if (!SGProfileIndexIsValid(profileIdx)) return NO;

    NSString *address = [serverAddress stringByTrimmingCharactersInSet:
                         [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (!SG_IsIdentifierStringSafe(address) ||
        [address lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > SGP_SERVER_ADDRESS_MAX_BYTES) {
        return NO;
    }

    BOOL hasNewCertificate = ([certificatePEM length] > 0);
    if (hasNewCertificate && !SG_CryptoCertificatePEMIsValid(certificatePEM)) return NO;

    BOOL isActive = ([[SGConfiguration sharedConfiguration] activeProfileIndex] == profileIdx);
    NSString *previousAddress = isActive
        ? [[SGConfiguration sharedConfiguration] serverAddress] : nil;
    BOOL addressChanged = (previousAddress && ![previousAddress isEqualToString:address]);

    BOOL credentialsInvalidated = NO;
    if (![_stateStore saveProfileAtIndex:profileIdx
                           serverAddress:address
                          certificatePEM:(hasNewCertificate ? certificatePEM : nil)
                  invalidatedCredentials:&credentialsInvalidated]) {
        return NO;
    }

    [[SGConfiguration sharedConfiguration] reloadFromDisk];

    if (isActive) {
        if (credentialsInvalidated) {
            [[SGDatabaseManager sharedManager] clearAllTokens];
        }

        if (addressChanged) {
            [[SGDatabaseManager sharedManager] clearAllDNSCache];
        }
        [self handleEvent:SGEventConfigReloaded payload:nil];
    }

    [_stateStore drainDurableEventInbox];
    return YES;
}

- (BOOL)performSetRegistrationIdentityAtIndex:(NSInteger)profileIdx
                                  identityPEM:(NSString *)identityPEM {
    if (!SGProfileIndexIsValid(profileIdx)) return NO;

    BOOL hasIdentity = ([identityPEM length] > 0);
    if (hasIdentity && !SG_CryptoIdentityPEMIsValid(identityPEM)) return NO;

    if (![_stateStore setRegistrationIdentityAtIndex:profileIdx
                                         identityPEM:(hasIdentity ? identityPEM : nil)]) {
        return NO;
    }

    if ([[SGConfiguration sharedConfiguration] activeProfileIndex] == profileIdx) {
        [[SGConfiguration sharedConfiguration] reloadFromDisk];

        [self handleEvent:SGEventConfigReloaded payload:nil];
    }
    return YES;
}

- (BOOL)performDeleteProfileAtIndex:(NSInteger)profileIdx {
    if (!SGProfileIndexIsValid(profileIdx)) return NO;

    SGConfiguration *configuration = [SGConfiguration sharedConfiguration];
    BOOL wasActive = ([configuration activeProfileIndex] == profileIdx);
    BOOL shouldQuiesce = wasActive && [configuration isEnabled];

    if (shouldQuiesce) {
        [self handleEvent:SGEventStopRequested payload:nil];
        dispatch_sync(_entryActionQueue, ^{});
    }

    BOOL removed = [_stateStore removeProfileAtIndex:profileIdx];

    if (wasActive) {
        [configuration reloadFromDisk];
        [_notificationProcessor resetInMemoryDeduplication];

        [self handleEvent:SGEventConfigReloaded payload:nil];
    }

    return removed;
}

- (BOOL)performSetActiveProfileAtIndex:(NSInteger)profileIdx {
    if (!SGProfileIndexIsValid(profileIdx)) return NO;

    NSString *profilePath = SGProfilePlistPathForIndex(profileIdx);
    if (![[NSFileManager defaultManager] fileExistsAtPath:profilePath]) return NO;

    if ([[SGConfiguration sharedConfiguration] activeProfileIndex] == profileIdx) return YES;

    BOOL persisted = [_stateStore updateMainPreferences:^(NSMutableDictionary *preferences) {
        [preferences setObject:[NSNumber numberWithInteger:profileIdx]
                        forKey:@"activeProfile"];
    }];
    if (!persisted) return NO;

    [[SGConfiguration sharedConfiguration] reloadFromDisk];

    [_notificationProcessor resetInMemoryDeduplication];
    [self reconcileTokensWithPlist];
    [self handleEvent:SGEventConfigReloaded payload:nil];
    [_notificationProcessor kickPendingDeliveryDrain];
    [_stateStore drainDurableEventInbox];
    return YES;
}

#pragma mark - Notification Delivery

- (SGControlError)_deliverPushTopic:(NSString *)topic payload:(NSDictionary *)payload {
    if (!topic || [topic length] == 0) return SGCERR_INVALID_REQUEST;

    if (!_deliveryPlatform) {
        SGLOGW(SGDaemon, "code=%s bundle=%s result=unavailable", SGND_DELIVERY_PLATFORM_UNAVAILABLE,
                    [topic length] ? [topic UTF8String] : "none");
        return SGCERR_UNREACHABLE;
    }

    SGControlError kr = [_deliveryPlatform
        sendNotificationForBundleID:topic payload:payload];
    SGLOGI(SGDaemon, "code=%s bundle=%s result=%s", SGND_DELIVERY_DISPATCHING,
                [topic UTF8String], (kr == SGCERR_OK) ? "delivered" : "failed");
    return kr;
}

#pragma mark - Keepalive Algorithm Helpers

- (double)_currentKeepAliveInterval {
    return [[SGAvailability shared] currentIntervalForGrowthAlgorithm:_growthAlgorithm];
}

- (void)_processKeepAliveResult:(BOOL)success {
    [[SGAvailability shared] processResult:success forGrowthAlgorithm:_growthAlgorithm];
}

- (void)_reinitializeKeepAliveForWiFi:(BOOL)isWiFi savedInterval:(double)savedInterval {
    [_growthAlgorithm release];
    _growthAlgorithm = [[SGAvailability shared]
        reinitializeGrowthAlgorithmForWiFi:isWiFi
                             savedInterval:savedInterval];
}

#pragma mark - PCPersistentTimer Keepalive (Survives Deep Sleep)

- (void)_scheduleKeepAliveTimer {
    if (![SGAvailability shared].persistentTimerAvailable) return;

    [_stateLock lock];
    double interval = [self _currentKeepAliveInterval];
    uint32_t generation = _fsmGeneration;
    [_stateLock unlock];

    dispatch_async(dispatch_get_main_queue(), ^{
        BOOL stale = [self _generationIsStale:generation];

        SGStatusPayload status;
        SGStatusServer_Current(&status);
        if (stale || status.state != SGStateConnected || !SGP_IsConnected()) {
            SGLOGD(SGDaemon, "code=%s generation=%u action=discard",
                   SGND_KEEPALIVE_TIMER_IGNORED, generation);
            return;
        }

        if (self->_keepAliveTimer) {
            [self->_keepAliveTimer invalidate];
            [self->_keepAliveTimer release];
            self->_keepAliveTimer = nil;
        }

        self->_keepAliveTimer = [[SGAvailability shared]
            createPersistentTimerWithInterval:interval
                           serviceIdentifier:@"com.skyglow.sgn"
                                      target:self
                                    selector:@selector(_keepAliveTimerFired:)];

        if (!self->_keepAliveTimer) return;

        [[SGAvailability shared] schedulePersistentTimer:self->_keepAliveTimer inRunLoop:[NSRunLoop mainRunLoop]];

        SGLOGI(SGDaemon, "code=%s interval=%.0fs result=scheduled", SGND_KEEPALIVE_TIMER_SCHEDULED, interval);
    });
}

- (void)_invalidateKeepAliveTimer {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self->_keepAliveTimer) {
            [self->_keepAliveTimer invalidate];
            [self->_keepAliveTimer release];
            self->_keepAliveTimer = nil;
        }
    });
}

- (void)_keepAliveTimerFired:(id)timer {
    if (timer != _keepAliveTimer || !SGP_IsConnected()) {
        SGLOGD(SGDaemon, "code=%s reason=stale_or_not_connected action=ignore", SGND_KEEPALIVE_TIMER_IGNORED);
        return;
    }

    double pendingAge = SGP_GetPendingPingAgeWallSeconds();
    if (pendingAge > (double)SGP_PONG_TIMEOUT_SEC) {
        SGLOGW(SGDaemon, "code=%s pending=%.0fs action=probe", SGND_KEEPALIVE_STALE_PING, pendingAge);
        [self _probeConnectionLiveness];
        [self _scheduleKeepAliveTimer];
        return;
    }

    if (SGKAOffload_IsActive()) {
        SGLOGD(SGDaemon, "code=%s action=skip_ping_offload_active", SGND_KEEPALIVE_OFFLOAD_SUPPRESS_WAKE);
        [self _scheduleKeepAliveTimer];
        return;
    }

    SGLOGD(SGDaemon, "code=%s action=send_ping", SGND_KEEPALIVE_TIMER_FIRED);
    if (!SGP_SendKeepAlivePing()) {
        SGLOGD(SGDaemon, "code=%s reason=pending_or_send_failed", SGND_KEEPALIVE_PING_SKIPPED);
    }

    [self _scheduleKeepAliveTimer];
}

- (void)_releaseProbeAssertion:(uint32_t)assertionID {
    if (!assertionID) return;
    uint32_t expected = assertionID;
    if (atomic_compare_exchange_strong(&_probeAssertionID, &expected, 0)) {
        [[SGAvailability shared] releasePowerAssertion:assertionID];
    }
}

- (void)_probeConnectionLiveness {
    bool expected = false;
    if (!atomic_compare_exchange_strong(&_probeInFlight, &expected, true)) {
        SGLOGD(SGDaemon, "code=%s action=coalesce_existing_probe", SGND_KEEPALIVE_PROBE);
        return;
    }
    uint64_t connectionGeneration = SGP_GetConnectionGeneration();

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        if (!SGP_IsConnected() ||
            SGP_GetConnectionGeneration() != connectionGeneration) {
            atomic_store(&self->_probeInFlight, false);
            return;
        }

        uint32_t assertionID = [[SGAvailability shared]
            createTimedPowerAssertionWithName:@"com.skyglow.sgn.probe"
                                      timeout:SG_POWER_ASSERTION_TIMEOUT_SEC];
        uint32_t previous = atomic_exchange(&_probeAssertionID, assertionID);
        if (previous) [[SGAvailability shared] releasePowerAssertion:previous];

        SGP_SendKeepAlivePing();

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                     (int64_t)((SGP_PONG_TIMEOUT_SEC + 5) * NSEC_PER_SEC)),
                       dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            double stillPending = SGP_GetPendingPingAgeWallSeconds();
            BOOL sameConnection =
                (SGP_GetConnectionGeneration() == connectionGeneration);
            if (sameConnection && SGP_IsConnected() &&
                stillPending > (double)SGP_PONG_TIMEOUT_SEC) {
                SGLOGW(SGDaemon, "code=%s pending=%.0fs action=abort_for_reconnect",
                       SGND_KEEPALIVE_PROBE_FAILED, stillPending);
                [self _recordKeepAliveFailureFeedback];
                SGP_AbortConnection();
            }
            [self _releaseProbeAssertion:assertionID];
            atomic_store(&self->_probeInFlight, false);
        });
    });
}

- (void)_recordKeepAliveFailureFeedback {
    [_stateLock lock];
    double oldVal = [self _currentKeepAliveInterval];
    [self _processKeepAliveResult:NO];
    double newVal = [self _currentKeepAliveInterval];
    BOOL isWiFi = _isWiFi;
    [_stateLock unlock];

    if (newVal != oldVal) {
        [[SGDatabaseManager sharedManager] saveKeepAliveInterval:newVal forWiFi:isWiFi];
        SGLOGI(SGDaemon, "code=%s old=%.0fs new=%.0fs", SGND_KEEPALIVE_INTERVAL_BACKOFF, oldVal, newVal);
    }
}

- (void)performDNSResolution {
    NSString *address = [[SGConfiguration sharedConfiguration] serverAddress];
    if (!address) {
        [self handleEvent:SGEventDNSFailed payload:nil];
        return;
    }

    uint32_t gen = [self _captureGeneration];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSDictionary *txt = [SGServerLocator resolveEndpointForServerAddress:address];

        if ([self _generationIsStale:gen]) return;

        if (txt && isValidPort(txt[@"tcp_port"])) {
            [self handleEvent:SGEventDNSResolved payload:txt];
        } else {
            [self handleEvent:SGEventDNSFailed payload:nil];
        }
    });
}

- (void)performSocketConnection {
    NSString *ip = [[SGConfiguration sharedConfiguration] serverIPAddress];
    NSString *portStr = [[SGConfiguration sharedConfiguration] serverPort];
    NSString *cert = [[SGConfiguration sharedConfiguration] serverPubKeyPEM];

    if (!ip || !portStr || !cert) {
        SGLOGE(SGDaemon, "code=%s ip=%s port=%s cert=%s result=failed", SGND_CONFIG_BAD_SERVER_FIELDS,
                    ip ? "set" : "missing",
                    portStr ? "set" : "missing",
                    cert ? "set" : "missing");
        strlcpy(_lastErrorDetail, "Missing server IP, port, or certificate", sizeof(_lastErrorDetail));
        [self handleEvent:SGEventConnectFailed payload:nil];
        return;
    }

    uint32_t gen = [self _captureGeneration];

    NSString *ipCopy   = [ip copy];
    NSString *certCopy = [cert copy];
    int port = [portStr intValue];

    NSString *regIdentityCopy = nil;
    if ([[[SGConfiguration sharedConfiguration] deviceAddress] length] == 0) {
        regIdentityCopy = [[[SGConfiguration sharedConfiguration] registrationIdentityPEM] copy];
    }

    dispatch_async(_connectionQueue, ^{
        @autoreleasepool {
            if ([self _generationIsStale:gen]) {
                [ipCopy release];
                [certCopy release];
                [regIdentityCopy release];
                return;
            }

            SGP_SetRegistrationIdentity(regIdentityCopy);
            [regIdentityCopy release];
            int rc = SGP_ConnectToServer([ipCopy UTF8String], port, certCopy);
            [certCopy release];

            if ([self _generationIsStale:gen]) {
                if (rc == 0) {
                    SGP_DisconnectFromServer();
                }
                [ipCopy release];
                return;
            }

            if (rc == 0) {
                SGLOGI(SGDaemon, "code=%s ip=%s port=%d result=connected", SGND_PROTOCOL_CONNECT_SUCCEEDED, [ipCopy UTF8String], port);
                [self handleEvent:SGEventConnectSuccess payload:nil];
            } else {
                SGLOGW(SGDaemon, "code=%s ip=%s port=%d rc=%d name=%s result=failed", SGND_PROTOCOL_CONNECT_FAILED,
                            [ipCopy UTF8String], port, rc, SGP_ConnectErrorName(rc));

                NSString *serverAddr = [[SGConfiguration sharedConfiguration] serverAddress];
                if (rc == -9 || rc == -10) {
                    SGLOGW(SGDaemon, "code=%s rc=%d action=purge_dns_cache",
                           SGND_PROTOCOL_CONNECT_FAILED, rc);
                    [[SGDatabaseManager sharedManager] clearAllDNSCache];
                }
                [SGServerLocator refreshDNSCacheAsynchronouslyForAddress:serverAddr];

                SGFailureClass cls = SGFailureClassForOSError(SGP_GetLastConnectOSError());
                [self handleEvent:SGEventConnectFailed
                          payload:[NSNumber numberWithInt:(int)cls]];
            }
            [ipCopy release];
        }
    });
}

- (void)startConnectionScopedWorker {
    uint64_t connectionGeneration = SGP_GetConnectionGeneration();

    dispatch_async(_protocolWorkerQueue, ^{
        if (!SGP_IsConnected() ||
            SGP_GetConnectionGeneration() != connectionGeneration) {
            return;
        }

        SGLOGI(SGDaemon, "code=%s generation=%llu result=started",
               SGND_PROTOCOL_WORKER_STARTED,
               (unsigned long long)connectionGeneration);

        BOOL timerDrivenPings = [SGAvailability shared].persistentTimerAvailable;

        while (SGP_IsConnected() &&
               SGP_GetConnectionGeneration() == connectionGeneration) {
            @autoreleasepool {
                double pingInterval = 0.0;
                if (!timerDrivenPings) {
                    [self->_stateLock lock];
                    pingInterval = [self _currentKeepAliveInterval];
                    [self->_stateLock unlock];
                }

                int rc = SGP_ProcessNextIncomingMessage(pingInterval);

                if (rc != SGP_OK) {
                    BOOL isCurrentConnection =
                        (SGP_GetConnectionGeneration() == connectionGeneration);
                    SGLOGI(SGDaemon, "code=%s generation=%llu rc=%d name=%s current=%s result=exited",
                           SGND_PROTOCOL_WORKER_EXITED,
                           (unsigned long long)connectionGeneration,
                           rc, SGP_ErrorName(rc),
                           isCurrentConnection ? "yes" : "no");
                    if (isCurrentConnection) {
                        if (rc == SGP_ERR_TIMEOUT) {
                            [self _recordKeepAliveFailureFeedback];
                        }
                        if (rc == SGP_ERR_AUTH) {
                            [self handleEvent:SGEventAuthFailed payload:nil];
                        } else if (rc == SGP_ERR_VERSION_MISMATCH) {
                            [self handleEvent:SGEventVersionMismatch payload:nil];
                        } else {
                            [self handleEvent:SGEventDisconnected payload:nil];
                        }
                    }
                    break;
                }
            }
        }
        SGLOGI(SGDaemon, "code=%s generation=%llu result=stopped",
               SGND_PROTOCOL_WORKER_STOPPED,
               (unsigned long long)connectionGeneration);
    });
}

- (void)scheduleTimerForEvent:(SGEvent)event
                        delay:(uint32_t)seconds
                leewayPercent:(uint32_t)leewayPercent
                   generation:(uint32_t)generation {
    dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
    if (!timer) return;

    uint64_t leewayNsec = (uint64_t)seconds * NSEC_PER_SEC / 100 * leewayPercent;
    dispatch_source_set_timer(timer,
                              dispatch_walltime(NULL, (int64_t)seconds * (int64_t)NSEC_PER_SEC),
                              DISPATCH_TIME_FOREVER, leewayNsec);
    dispatch_source_set_event_handler(timer, ^{
        dispatch_source_cancel(timer);
        dispatch_release(timer);
        if ([self _generationIsStale:generation]) {
            SGLOGD(SGDaemon, "code=%s generation=%u event=%ld action=discard", SGND_FSM_TIMER_STALE, generation, (long)event);
            return;
        }
        [self handleEvent:event payload:nil];
    });
    dispatch_resume(timer);
}

@end
