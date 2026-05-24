#import "SGDaemon.h"
#import "SGConfiguration.h"
#import "SGDatabaseManager.h"
#import "SGTokenManager.h"
#import "SGProtocolHandler.h"
#import "SGServerLocator.h"
#import "SGPayloadParser.h"
#import "SGCryptoEngine.h"
#import "SGAvailability.h"
#import "SGControlChannel.h"
#import "SGLog.h"
#include <openssl/pem.h>
#include <unistd.h>
#include <fcntl.h>

static const int64_t       kSGDrainSafetyIntervalSec              = 300;   // fallback only; primary drains are event-driven
static const int64_t       kSGDrainSafetyLeewaySec                 =  30;
static const int64_t       kSGLocalPendingFallbackDeadlineSec      = 86400; // 24h when wire has no expiry
static const NSUInteger    kSGSeenMessageIDCap                     = 200;
static const uint32_t      kSGAuthTimeoutSec                       = 30;    // silent timeout; SGEventAuthFailed wipes the profile instead
static const uint32_t      kSGDNSWatchdogSec                       = 30;
static const NSTimeInterval kSGNotificationProcessingAssertionSec  = 15.0;

typedef struct { SGState from; SGState to; } SGTransition;

static const SGTransition kLegalTransitions[] = {
    { SGStateStarting,          SGStateDisabled            },
    { SGStateStarting,          SGStateIdleUnregistered    },
    { SGStateStarting,          SGStateResolvingDNS        },
    { SGStateStarting,          SGStateIdleDNSFailed       },
    { SGStateStarting,          SGStateIdleNoNetwork       },
    { SGStateStarting,          SGStateError               },
    { SGStateStarting,          SGStateErrorBadConfig      },

    { SGStateResolvingDNS,      SGStateResolvingDNS        },
    { SGStateResolvingDNS,      SGStateConnecting          },
    { SGStateResolvingDNS,      SGStateBackingOff          },
    { SGStateResolvingDNS,      SGStateIdleCircuitOpen     },
    { SGStateResolvingDNS,      SGStateErrorBadConfig      },
    { SGStateResolvingDNS,      SGStateIdleNoNetwork       },
    { SGStateResolvingDNS,      SGStateDisabled            },

    { SGStateIdleDNSFailed,     SGStateResolvingDNS        },
    { SGStateIdleDNSFailed,     SGStateDisabled            },
    { SGStateIdleDNSFailed,     SGStateIdleNoNetwork       },

    { SGStateIdleNoNetwork,     SGStateConnecting          },
    { SGStateIdleNoNetwork,     SGStateDisabled            },
    { SGStateIdleNoNetwork,     SGStateResolvingDNS        },

    { SGStateIdleUnregistered,  SGStateResolvingDNS        },
    { SGStateIdleUnregistered,  SGStateDisabled            },

    { SGStateConnecting,        SGStateResolvingDNS        },
    { SGStateConnecting,        SGStateAuthenticating      },
    { SGStateConnecting,        SGStateRegistering         },
    { SGStateConnecting,        SGStateBackingOff          },
    { SGStateConnecting,        SGStateIdleNoNetwork       },
    { SGStateConnecting,        SGStateIdleCircuitOpen     },
    { SGStateConnecting,        SGStateErrorBadConfig      },

    { SGStateRegistering,       SGStateAuthenticating      }, 
    { SGStateRegistering,       SGStateBackingOff          }, 
    { SGStateRegistering,       SGStateError               }, 
    { SGStateRegistering,       SGStateIdleNoNetwork       },
    { SGStateRegistering,       SGStateDisabled            },

    { SGStateAuthenticating,    SGStateResolvingDNS        },
    { SGStateAuthenticating,    SGStateRegistering         },
    { SGStateAuthenticating,    SGStateConnected           },
    { SGStateAuthenticating,    SGStateBackingOff          },
    { SGStateAuthenticating,    SGStateErrorAuth           },
    { SGStateAuthenticating,    SGStateDisabled            },
    { SGStateAuthenticating,    SGStateIdleNoNetwork       },
    { SGStateAuthenticating,    SGStateIdleUnregistered    },
    { SGStateAuthenticating,    SGStateErrorBadConfig      },

    { SGStateConnected,         SGStateConnecting          }, 
    { SGStateConnected,         SGStateBackingOff          },
    { SGStateConnected,         SGStateIdleNoNetwork       },
    { SGStateConnected,         SGStateDisabled            },
    { SGStateConnected,         SGStateResolvingDNS        },

    { SGStateBackingOff,        SGStateConnecting          },
    { SGStateBackingOff,        SGStateResolvingDNS        },
    { SGStateBackingOff,        SGStateIdleNoNetwork       },
    { SGStateBackingOff,        SGStateIdleCircuitOpen     },
    { SGStateBackingOff,        SGStateDisabled            },

    { SGStateIdleCircuitOpen,   SGStateConnecting          },
    { SGStateIdleCircuitOpen,   SGStateIdleNoNetwork       },
    { SGStateIdleCircuitOpen,   SGStateDisabled            },
    { SGStateIdleCircuitOpen,   SGStateResolvingDNS        },

    { SGStateErrorAuth,         SGStateDisabled            },
    { SGStateErrorAuth,         SGStateResolvingDNS        },

    { SGStateErrorBadConfig,    SGStateDisabled            },
    { SGStateErrorBadConfig,    SGStateResolvingDNS        },

    { SGStateError,             SGStateDisabled            },
    { SGStateError,             SGStateResolvingDNS        },

    { SGStateDisabled,          SGStateResolvingDNS        },
    { SGStateDisabled,          SGStateIdleUnregistered    },
    { SGStateDisabled,          SGStateErrorBadConfig      },
};

static const size_t kLegalTransitionCount = sizeof(kLegalTransitions) / sizeof(kLegalTransitions[0]);

static BOOL isLegalTransition(SGState from, SGState to) {
    if (to == SGStateShuttingDown) return YES;
    if (from == SGStateStarting) return YES;
    for (size_t i = 0; i < kLegalTransitionCount; i++) {
        if (kLegalTransitions[i].from == from && kLegalTransitions[i].to == to) return YES;
    }
    return NO;
}

static BOOL isValidPort(NSString *port) {
    if (!port || [port length] == 0) return NO;
    NSCharacterSet *nonDigits = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
    if ([port rangeOfCharacterFromSet:nonDigits].location != NSNotFound) return NO;
    int p = [port intValue];
    return (p > 0 && p <= 65535);
}

@implementation SGDaemon {
    NSLock                *_stateLock;
    int                    _consecutiveFailures;
    id                     _growthAlgorithm;
    NSMutableOrderedSet   *_seenMessageIDs;
    uint32_t               _fsmGeneration;
    BOOL                   _workerActive;
    dispatch_queue_t       _entryActionQueue;
    id                     _keepAliveTimer;
    BOOL                   _isWiFi;
    char                   _lastErrorDetail[128];
    dispatch_source_t      _localDeliveryRetryTimer;
    dispatch_queue_t       _localDeliveryDrainQueue;
    SGControlChannel      *_controlChannel;
    SGControlChannel      *_springBoardClient;
}

- (id)init {
    if ((self = [super init])) {
        _stateLock           = [[NSLock alloc] init];
        _consecutiveFailures = 0;
        _fsmGeneration       = 0;
        _seenMessageIDs      = [[NSMutableOrderedSet alloc] initWithCapacity:kSGSeenMessageIDCap];
        _entryActionQueue    = dispatch_queue_create("com.skyglow.daemon.entry", DISPATCH_QUEUE_SERIAL);
        _localDeliveryDrainQueue = dispatch_queue_create("com.skyglow.daemon.drain", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)dealloc {
    [_stateLock release];
    [_seenMessageIDs release];
    [_growthAlgorithm release];
    [_controlChannel release];
    [_springBoardClient release];
    if (_keepAliveTimer) { [_keepAliveTimer invalidate]; [_keepAliveTimer release]; }
    [self _stopLocalDeliveryRetryTimer];
    dispatch_release(_entryActionQueue);
    if (_localDeliveryDrainQueue) dispatch_release(_localDeliveryDrainQueue);
    [super dealloc];
}

- (void)attachControlChannel:(SGControlChannel *)channel {
    if (channel == _controlChannel) return;
    [channel retain];
    [_controlChannel release];
    _controlChannel = channel;
}

- (void)attachSpringBoardClient:(SGControlChannel *)client {
    if (client == _springBoardClient) return;
    [client retain];
    [_springBoardClient release];
    _springBoardClient = client;

    if (client) {
        __unsafe_unretained SGDaemon *daemonSelf = self;
        [client setConnectionHandler:^(BOOL connected) {
            if (!connected) return;
            if (daemonSelf->_controlChannel) {
                [daemonSelf->_controlChannel postEvent:SGCEVT_SB_RECEIVER_READY payload:nil];
            }
            [daemonSelf _kickLocalDeliveryDrain];
        }];
    }
}

- (void)start {
    [self _startLocalDeliveryRetryTimer];

    [self reconcileTokensWithPlist];
    
    [_stateLock lock];
    _isWiFi = YES;
    double savedInterval = [[SGDatabaseManager sharedManager] loadKeepAliveIntervalForWiFi:YES];
    double initialInterval = (savedInterval > 0.0) ? savedInterval : 600.0;

    _growthAlgorithm = [[SGAvailability shared]
        createGrowthAlgorithmWithInterval:initialInterval
                          minimumInterval:600.0
                          maximumInterval:1680.0];
    [_stateLock unlock];
    
    [self handleEvent:SGEventStartRequested payload:nil];
}

- (void)reconcileTokensWithPlist {
    NSString *plistPath = SGPath(@"/var/mobile/Library/Preferences/com.skyglow.sndp.plist");
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    NSDictionary *appStatus = [prefs objectForKey:@"appStatus"] ?: @{};
    
    NSMutableSet *plistBundles = [NSMutableSet set];
    for (NSString *bundleID in appStatus) {
        if ([[appStatus objectForKey:bundleID] boolValue]) {
            [plistBundles addObject:bundleID];
        }
    }
    
    SGDatabaseManager *db = [SGDatabaseManager sharedManager];
    NSSet *dbBundles = [db registeredBundleIdentifiers];
    
    for (NSString *bundleID in dbBundles) {
        if (![plistBundles containsObject:bundleID]) {
            [db removeTokenForBundleIdentifier:bundleID];
            SGLOGI(SGDaemon, "Removed orphaned token for: %s", [bundleID UTF8String]);
        }
    }
    
    NSString *serverAddr = [[SGConfiguration sharedConfiguration] serverAddress];
    if (serverAddr && [serverAddr length] > 0) {
        SGTokenManager *tokenMgr = [[SGTokenManager alloc] init];
        for (NSString *bundleID in plistBundles) {
            if (![dbBundles containsObject:bundleID]) {
                NSError *err = nil;
                NSData *token = [tokenMgr synchronizedTokenForBundleIdentifier:bundleID error:&err];
                if (token) {
                    SGLOGI(SGDaemon, "Generated missing token for: %s", [bundleID UTF8String]);
                } else {
                    SGLOGE(SGDaemon, "Failed to generate token for %s: %s",
                           [bundleID UTF8String], [[err description] UTF8String]);
                }
            }
        }
        [tokenMgr release];
    } else {
        for (NSString *bundleID in plistBundles) {
            if (![dbBundles containsObject:bundleID]) {
                SGLOGI(SGDaemon, "App %s needs a token but device is unregistered — will generate after registration", [bundleID UTF8String]);
            }
        }
    }
}

- (void)handleEvent:(SGEvent)event payload:(id)payload {
    [_stateLock lock];
    
    SGStatusPayload currentStatus;
    SGStatusServer_Current(&currentStatus);
    SGState currentState = (SGState)currentStatus.state;
    
    SGLOGD(SGDaemon, "FSM Rx Event: %ld in State: %s", (long)event, SGState_GetName(currentState));

    if (event == SGEventStopRequested ||
       (event == SGEventConfigReloaded && ![[SGConfiguration sharedConfiguration] isEnabled])) {
        _consecutiveFailures = 0;
        strlcpy(_lastErrorDetail, "Daemon is disabled", sizeof(_lastErrorDetail));
        [self executeTransitionToState:SGStateDisabled backoff:0 ip:NULL];
        [_stateLock unlock];
        return;
    }

    if (event == SGEventNetworkDown) {
        if (currentState != SGStateDisabled && currentState != SGStateErrorBadConfig) {
            strlcpy(_lastErrorDetail, "No network connection available", sizeof(_lastErrorDetail));
            [self executeTransitionToState:SGStateIdleNoNetwork backoff:0 ip:NULL];
        }
        [_stateLock unlock];
        return;
    }

    switch (currentState) {
        case SGStateStarting:
        case SGStateDisabled:
        case SGStateErrorBadConfig:
        case SGStateIdleUnregistered:
            if (event == SGEventStartRequested || event == SGEventConfigReloaded) {
                _consecutiveFailures = 0;
                if ([[SGConfiguration sharedConfiguration] isValid]) {
                    _lastErrorDetail[0] = '\0';
                    [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
                } else {
                    strlcpy(_lastErrorDetail, "Missing server address or certificate", sizeof(_lastErrorDetail));
                    [self executeTransitionToState:SGStateErrorBadConfig backoff:0 ip:NULL];
                }
            }
            break;

        case SGStateIdleNoNetwork:
            if (event == SGEventNetworkUp) {
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            }
            break;

        case SGStateResolvingDNS:
            if (event == SGEventConfigReloaded) {
                _consecutiveFailures = 0;
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            } else if (event == SGEventDNSResolved) {
                NSDictionary *txt = (NSDictionary *)payload;
                [[SGConfiguration sharedConfiguration] setServerIPAddress:txt[@"tcp_addr"]];
                [[SGConfiguration sharedConfiguration] setServerPort:txt[@"tcp_port"]];
                [self executeTransitionToState:SGStateConnecting backoff:0 ip:[txt[@"tcp_addr"] UTF8String]];
            } else if (event == SGEventDNSFailed) {
                strlcpy(_lastErrorDetail, "DNS resolution failed", sizeof(_lastErrorDetail));
                [self executeFailureBackoff];
            }
            break;

        case SGStateIdleDNSFailed:
        case SGStateBackingOff:
            if (event == SGEventConfigReloaded) {
                _consecutiveFailures = 0;
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            } else if (event == SGEventBackoffTimerFired || event == SGEventNetworkUp) {
                if (event == SGEventNetworkUp) _consecutiveFailures = 0;
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            } else if (event == SGEventSystemDidWake) {
                /**
                 * Device woke from deep sleep while a backoff timer was pending.
                 * Skip the remaining wait and retry immediately — the system wake
                 * implies enough time has passed that a retry is reasonable.
                 * Unlike SGEventNetworkUp this does NOT reset _consecutiveFailures:
                 * the server may still be unreachable; the circuit breaker count
                 * is preserved so we still reach SGStateIdleCircuitOpen eventually.
                 */
                SGLOGI(SGDaemon, "System wake received during backoff — skipping remaining wait.");
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            }
            break;

        case SGStateConnecting:
            if (event == SGEventConfigReloaded) {
                _consecutiveFailures = 0;
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            } else if (event == SGEventConnectSuccess) {
                [self executeTransitionToState:SGStateAuthenticating backoff:0 ip:NULL];
            } else if (event == SGEventConnectFailed || event == SGEventDisconnected) {
                strlcpy(_lastErrorDetail, "Connection to server failed", sizeof(_lastErrorDetail));
                [self executeFailureBackoff];
            }
            break;

        case SGStateAuthenticating:
            if (event == SGEventConfigReloaded) {
                _consecutiveFailures = 0;
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            } else if (event == SGEventAuthSuccess) {
                _consecutiveFailures = 0;
                _lastErrorDetail[0] = '\0';
                [self executeTransitionToState:SGStateConnected backoff:0 ip:NULL];
            } else if (event == SGEventAuthFailed) {
                strlcpy(_lastErrorDetail, "Server rejected authentication \xe2\x80\x94 key may be revoked", sizeof(_lastErrorDetail));
                [self performProfileWipeInline];
                [self executeFailureBackoff];
            } else if (event == SGEventAuthTimeout) {
                strlcpy(_lastErrorDetail, "Authentication timed out (30s)", sizeof(_lastErrorDetail));
                [self executeFailureBackoff];
            } else if (event == SGEventDisconnected) {
                strlcpy(_lastErrorDetail, "Disconnected during authentication", sizeof(_lastErrorDetail));
                [self executeFailureBackoff];
            }
            break;

        case SGStateConnected:
            if (event == SGEventConfigReloaded) {
                _consecutiveFailures = 0;
                _lastErrorDetail[0] = '\0';
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            } else if (event == SGEventDisconnected) {
                strlcpy(_lastErrorDetail, "Connection lost", sizeof(_lastErrorDetail));
                [self executeFailureBackoff];
            }
            break;
            
        case SGStateErrorAuth:
            if (event == SGEventConfigReloaded) {
                /**
                 * A config reload (user changed server settings or re-enabled the
                 * daemon) is the natural recovery path from an auth error. The new
                 * config may have a different server or different credentials, so
                 * retry from scratch. _consecutiveFailures is reset so the fresh
                 * attempt gets a full set of retries before the circuit opens again.
                 *
                 * SGStateErrorAuth → SGStateResolvingDNS is a legal transition.
                 * Without this case, the daemon would stay stuck indefinitely after
                 * an explicit server auth rejection unless the process was restarted.
                 */
                _consecutiveFailures = 0;
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            }
            break;

        case SGStateIdleCircuitOpen:
            if (event == SGEventNetworkUp || event == SGEventConfigReloaded) {
                _consecutiveFailures = 0;
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            } else if (event == SGEventSystemDidWake) {
                /**
                 * The device woke from deep sleep while the circuit breaker was open.
                 * The network interface is almost certainly still available (same WiFi),
                 * but the server may have recovered while we were asleep — or the device
                 * may have moved to a different network without triggering a change event.
                 *
                 * This is NOT SGEventNetworkUp: the network has not changed. We are not
                 * lying to the FSM. This is a distinct "enough time has passed, try again"
                 * trigger that exists specifically for the wake-from-sleep case.
                 *
                 * From all other states this event is a no-op (handled by the default
                 * case below), so IOKit can fire it on every wake without wasted work.
                 */
                SGLOGI(SGDaemon, "System wake received in circuit-open idle — resetting failures and retrying.");
                _consecutiveFailures = 0;
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            }
            break;

        default:
            break;
    }
    
    [_stateLock unlock];
}

- (void)executeTransitionToState:(SGState)newState backoff:(uint32_t)backoff ip:(const char *)ip {
    SGStatusPayload current;
    SGStatusServer_Current(&current);
    if (!isLegalTransition((SGState)current.state, newState) && current.state != newState) {
        SGLOGE(SGDaemon, "ILLEGAL TRANSITION REJECTED: %s -> %s",
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

    uint32_t activeProfile = (uint32_t)[[SGConfiguration sharedConfiguration] activeProfileIndex];
    SGStatusServer_Post(newState, (uint32_t)_consecutiveFailures, backoff,
                        resolvedIP, _lastErrorDetail, activeProfile);
    SGLOGD(SGDaemon, "Transitioned to %s (gen=%u)", SGState_GetName(newState), capturedGen);

    if (_controlChannel) {
        SGCStateChangedEventData ev;
        memset(&ev, 0, sizeof(ev));
        ev.newState = (uint8_t)newState;
        strlcpy(ev.reason, _lastErrorDetail, sizeof(ev.reason));
        NSData *payload = [NSData dataWithBytes:&ev length:sizeof(ev)];
        [_controlChannel postEvent:SGCEVT_STATE_CHANGED payload:payload];
    }

    dispatch_async(_entryActionQueue, ^{
        [self->_stateLock lock];
        BOOL isStale = (self->_fsmGeneration != capturedGen);
        [self->_stateLock unlock];
        if (isStale) return;

        [self _invalidateKeepAliveTimer];

        switch (newState) {
            case SGStateResolvingDNS:
                SGP_AbortConnection();
                [self performDNSResolution];
                break;
            case SGStateConnecting:
                [self performSocketConnection];
                break;    
            case SGStateAuthenticating:
                [self startConnectionScopedWorker];
                /**
                 * kSGAuthTimeoutSec fires SGEventAuthTimeout, not SGEventAuthFailed.
                 * SGEventAuthFailed is reserved for explicit server rejection and
                 * triggers a profile wipe. A silent timeout is ambiguous — the
                 * credential is presumed valid; we just back off and retry.
                 */
                [self scheduleTimerForEvent:SGEventAuthTimeout delay:kSGAuthTimeoutSec generation:capturedGen];
                break;
            case SGStateRegistering:
                break;
            case SGStateConnected:
                [self _scheduleKeepAliveTimer];
                break;
            case SGStateBackingOff:
            case SGStateIdleDNSFailed:
                /**
                 * Abort any in-progress connection (e.g. auth timed out while
                 * the socket was still open). SGP_AbortConnection is idempotent —
                 * safe to call when already disconnected.
                 */
                SGP_AbortConnection();
                [self scheduleTimerForEvent:SGEventBackoffTimerFired delay:backoff generation:capturedGen];
                break;
            case SGStateIdleCircuitOpen:
                SGP_AbortConnection();
                break;
            case SGStateDisabled:
            case SGStateIdleNoNetwork:
            case SGStateErrorBadConfig:
            case SGStateErrorAuth:
                SGP_AbortConnection(); 
                break;
            default:
                break;
        }
    });
}

- (void)executeFailureBackoff {
    _consecutiveFailures++;
    
    if (_consecutiveFailures >= SG_MAX_CONSECUTIVE_FAILURES) {
        SGLOGW(SGDaemon, "Max failures (%d) reached after ~1h. Idling until network change.", SG_MAX_CONSECUTIVE_FAILURES);
        strlcpy(_lastErrorDetail, "Too many consecutive failures \xe2\x80\x94 paused", sizeof(_lastErrorDetail));
        [self executeTransitionToState:SGStateIdleCircuitOpen backoff:0 ip:NULL];
    } 
    else {
        uint32_t baseDelay = (uint32_t)SG_INITIAL_BACKOFF_SECONDS * ((uint32_t)1 << (_consecutiveFailures - 1));
        uint32_t jitter = arc4random_uniform(SG_MAX_JITTER_SECONDS + 1);
        uint32_t finalDelay = baseDelay + jitter;
        if (finalDelay > SG_MAX_BACKOFF_SECONDS) {
            finalDelay = SG_MAX_BACKOFF_SECONDS;
        }

        uint32_t serverHint = SGP_GetLastDisconnectRetryAfter();
        if (serverHint > finalDelay) {
            finalDelay = serverHint;
            SGLOGI(SGDaemon, "Server requested retry-after %us, honoring.", serverHint);
        }

        SGLOGI(SGDaemon, "Backing off for %u seconds (Failure %d/%d)", finalDelay, _consecutiveFailures, SG_MAX_CONSECUTIVE_FAILURES);
        [self executeTransitionToState:SGStateBackingOff backoff:finalDelay ip:NULL];
    }
}

- (void)protocolDidReceiveWelcomeChallenge {
    NSString *clientAddress = [[SGConfiguration sharedConfiguration] deviceAddress];

    if (!clientAddress || [clientAddress length] == 0) {
        [_stateLock lock];
        [self executeTransitionToState:SGStateRegistering backoff:0 ip:NULL];
        [_stateLock unlock];
        
        NSString *proposed = SGP_BeginFirstTimeRegistration();
        if (!proposed) {
            [self handleEvent:SGEventDisconnected payload:nil];
        }
        return;
    }

    RSA *privKey = SG_CryptoGetClientPrivateKey();
    if (!privKey) {
        SGLOGW(SGDaemon, "Profile contains device_address but missing/invalid privateKey! Wiping profile for re-registration.");
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

    [self _kickLocalDeliveryDrain];
    [self uploadPendingTokensAsync];
}

- (void)protocolDidCompleteTokenRegistration:(NSString *)bundleIdentifier {
    SGLOGI(SGDaemon, "Token registration acknowledged for %s", [bundleIdentifier UTF8String]);
}

- (void)uploadPendingTokensAsync {
    NSArray *pending = [[SGDatabaseManager sharedManager] pendingUploadTokens];
    if ([pending count] == 0) return;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        for (NSDictionary *entry in pending) {
            @autoreleasepool {
                if (!SGP_IsConnected()) break;
                NSData   *routingKey = entry[@"routingKey"];
                NSString *bundleID   = entry[@"bundleID"];
                if (SGP_RegisterDeviceToken(routingKey, bundleID)) {
                    [[SGDatabaseManager sharedManager] markTokenAsUploaded:routingKey];
                }
            }
        }
    });
}

- (void)protocolDidReceiveNotification:(NSDictionary *)messageDict {
    @autoreleasepool {
        NSData *msgID = messageDict[@"msg_id"];
        if (!msgID || [msgID length] != SGP_MSG_ID_LEN) return;

        SGLOGI(SGDaemon, "Processing Push Notification (MSG_ID: %s)", [[msgID description] UTF8String]);

        SGDatabaseManager *db = [SGDatabaseManager sharedManager];

        /* Three-tier dedup: durable SQLite history → in-flight pending queue →
         * hot in-memory cache for retransmits arriving before the SQLite write
         * is observed.  The in-flight check stays silent because the drain
         * timer owns the ACK for those rows. */
        if ([db hasSeenMessageID:msgID]) {
            SGLOGD(SGDaemon, "Already-seen msg_id — re-ACKing SUCCESS without re-delivery.");
            SGP_EnqueueAcknowledgement(msgID, SGP_ACK_SUCCESS);
            return;
        }
        if ([db hasLocalPendingDeliveryForMessageID:msgID]) {
            SGLOGD(SGDaemon, "Retransmit of in-flight local-pending msg — dropping silently; drain timer owns the ACK.");
            return;
        }
        @synchronized(_seenMessageIDs) {
            if ([_seenMessageIDs containsObject:msgID]) {
                SGP_EnqueueAcknowledgement(msgID, SGP_ACK_SUCCESS);
                return;
            }
        }

        NSNumber *expiresAtNum = messageDict[@"expires_at"];
        int64_t expiresAt = expiresAtNum ? [expiresAtNum longLongValue] : 0;
        int64_t now = (int64_t)time(NULL);
        if (expiresAt > 0 && now > expiresAt) {
            SGLOGW(SGDaemon, "DROP: Notification expired %llds ago (expires_at=%lld now=%lld)",
                   now - expiresAt, expiresAt, now);
            SGP_EnqueueAcknowledgement(msgID, SGP_ACK_EXPIRED);
            [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
            return;
        }

        uint32_t assertionID = [[SGAvailability shared]
            createTimedPowerAssertionWithName:@"com.skyglow.sgn.processing"
                                     timeout:kSGNotificationProcessingAssertionSec];

        NSData *routingKey = messageDict[@"routing_key"];
        NSDictionary *routingData = [db tokenDataForRoutingKey:routingKey];
        if (!routingData) {
            SGLOGW(SGDaemon, "DROP: Routing Key not found in local Database.");
            goto cleanup_assertion;
        }

        NSData *payloadBytes = messageDict[@"data"];
        if (!payloadBytes) {
            SGLOGW(SGDaemon, "DROP: Payload data is empty.");
            SGP_EnqueueAcknowledgement(msgID, SGP_ACK_PARSE_FAILED);
            [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
            goto cleanup_assertion;
        }

        if ([messageDict[@"is_encrypted"] boolValue]) {
            SGLOGD(SGDaemon, "Payload is encrypted. Attempting AES-256-GCM decryption...");
            if ([payloadBytes length] < SGP_GCM_TAG_LEN) {
                SGLOGW(SGDaemon, "DROP: Encrypted payload too short for GCM tag (%lu < %d).",
                       (unsigned long)[payloadBytes length], SGP_GCM_TAG_LEN);
                SGP_EnqueueAcknowledgement(msgID, SGP_ACK_DECRYPT_FAILED);
                [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
                goto cleanup_assertion;
            }
            NSData *iv = messageDict[@"iv"];
            if (!iv) {
                SGLOGW(SGDaemon, "DROP: Missing IV for decryption.");
                SGP_EnqueueAcknowledgement(msgID, SGP_ACK_DECRYPT_FAILED);
                [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
                goto cleanup_assertion;
            }

            payloadBytes = SG_CryptoDecryptAESGCM(payloadBytes, routingData[@"e2eeKey"], iv, nil);
            if (!payloadBytes) {
                SGLOGE(SGDaemon, "DROP: Decryption failed (bad key or MAC tag tampering).");
                SGP_EnqueueAcknowledgement(msgID, SGP_ACK_DECRYPT_FAILED);
                [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
                goto cleanup_assertion;
            }
        } else {
            SGLOGD(SGDaemon, "Payload is plaintext TLV.");
        }

        NSDictionary *parsed = SG_PayloadParseBinaryData((const uint8_t *)payloadBytes.bytes, (uint32_t)payloadBytes.length);
        if (!parsed || parsed.count == 0) {
            SGLOGW(SGDaemon, "DROP: TLV parser returned empty dictionary. Malformed binary data?");
            SGP_EnqueueAcknowledgement(msgID, SGP_ACK_PARSE_FAILED);
            [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
            goto cleanup_assertion;
        }

        SGLOGI(SGDaemon, "Sending push to app [%s]: %s",
               [routingData[@"bundleID"] UTF8String], [[parsed description] UTF8String]);

        NSNumber *seqNum = messageDict[@"device_seq"];
        int64_t arrivedSeq = seqNum ? [seqNum longLongValue] : 0;

        kern_return_t deliveryKr = [self _deliverPushTopic:routingData[@"bundleID"] payload:parsed];
        if (deliveryKr == KERN_SUCCESS) {
            SGP_EnqueueAcknowledgement(msgID, SGP_ACK_SUCCESS);
            [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
            [self _advanceLastDeliveredSeqIfNeeded:arrivedSeq];

            [self _kickLocalDeliveryDrain];
        } else {
            /* Persist for retry rather than ACK SUCCESS for a banner the user
             * will never see; server retransmits during the window are absorbed
             * by hasLocalPendingDeliveryForMessageID: at the top of this method. */
            NSData *serialized = [NSPropertyListSerialization
                dataFromPropertyList:parsed
                              format:NSPropertyListBinaryFormat_v1_0
                    errorDescription:NULL];
            if (serialized) {
                int64_t effective = (expiresAt > now) ? expiresAt : (now + kSGLocalPendingFallbackDeadlineSec);
                [db enqueueLocalPendingDeliveryForMessageID:msgID
                                                   bundleID:routingData[@"bundleID"]
                                                    payload:serialized
                                                  deviceSeq:arrivedSeq
                                                  expiresAt:effective];
                SGLOGW(SGDaemon,
                       "Mach delivery failed kr=%d for %s — queued for local retry (deadline=%s).",
                       deliveryKr, [routingData[@"bundleID"] UTF8String],
                       (expiresAt > now) ? "wire expiry" : "fallback");
            } else {
                /* SG_PayloadParseBinaryData only emits plist-encodable types, so
                 * this is a corruption signal — degrade to PARSE_FAILED. */
                SGLOGE(SGDaemon,
                       "Mach delivery failed and payload not plist-encodable — ACKing PARSE_FAILED to halt server resends.");
                SGP_EnqueueAcknowledgement(msgID, SGP_ACK_PARSE_FAILED);
                [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
            }
        }

        cleanup_assertion:
        {
            [[SGAvailability shared] releasePowerAssertion:assertionID];
        }
    }
}


- (void)protocolDidReceiveKeepAlivePong {
    [_stateLock lock];
    double oldVal = [self _currentKeepAliveInterval];
    [self _processKeepAliveResult:YES];
    double newVal = [self _currentKeepAliveInterval];
    BOOL isWiFi = _isWiFi;
    [_stateLock unlock];
    
    if (newVal != oldVal) {
        [[SGDatabaseManager sharedManager] saveKeepAliveInterval:newVal forWiFi:isWiFi];
    }

    /**
     * Reschedule the PCPersistentTimer with the (possibly updated) interval.
     * This keeps the maintenance wake schedule in sync with the adaptive algorithm.
     * If the worker thread's select timeout sent the ping (not PCPersistentTimer),
     * we still need to ensure a PCPersistentTimer is pending for the next cycle.
     */
    [self _scheduleKeepAliveTimer];
}

- (void)protocolDidFinishOfflineQueueDrain {
    SGLOGI(SGDaemon, "Server confirmed all offline messages delivered.");
}

- (void)protocolDidReceiveTimeSyncWithOffset:(int64_t)offsetSeconds {
    if (llabs(offsetSeconds) > 60) {
        SGLOGW(SGDaemon, "Significant clock drift detected: %lld seconds", offsetSeconds);
    }
}

- (void)protocolDidCompleteRegistrationWithAddress:(NSString *)deviceAddress privateKey:(char *)pemKey serverVersion:(uint32_t)serverVersion {

    if (!pemKey) {
        [self handleEvent:SGEventDisconnected payload:nil];
        return;
    }

    size_t pemLen = strlen(pemKey);

    NSInteger profileIdx = [[SGConfiguration sharedConfiguration] activeProfileIndex];
    NSString *profilePath = SGPath([NSString stringWithFormat:
        @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile%ld.plist", (long)profileIdx]);
    NSMutableDictionary *profile = [NSMutableDictionary dictionaryWithContentsOfFile:profilePath] ?: [NSMutableDictionary dictionary];

    profile[@"device_address"] = deviceAddress;

    NSString *keyPath = [NSString stringWithFormat:
        @"/var/Library/PreferenceBundles/SGNPreferenceBundle.bundle/client_profile%ld.pem", (long)profileIdx];
    NSString *absoluteKeyPath = SGPath(keyPath);
    NSString *keyDir = [absoluteKeyPath stringByDeletingLastPathComponent];
    [[NSFileManager defaultManager] createDirectoryAtPath:keyDir withIntermediateDirectories:YES attributes:nil error:nil];

    BOOL keyWritten = NO;
    const char *keyPathC = [absoluteKeyPath fileSystemRepresentation];
    int fd = open(keyPathC, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        size_t written = 0;
        while (written < pemLen) {
            ssize_t n = write(fd, pemKey + written, pemLen - written);
            if (n <= 0) break;
            written += (size_t)n;
        }
        if (written == pemLen) {
            fsync(fd);
            keyWritten = YES;
        }
        close(fd);
    }

    SGP_ZeroAndFreeKeyMaterial(pemKey, pemLen);
    pemKey = NULL;

    if (!keyWritten) {
        SGLOGE(SGDaemon, "Failed to write private key to disk — aborting registration.");
        [[NSFileManager defaultManager] removeItemAtPath:absoluteKeyPath error:nil];
        [self handleEvent:SGEventDisconnected payload:nil];
        return;
    }

    profile[@"privateKey"] = keyPath;

    if (![profile writeToFile:profilePath atomically:YES]) {
        [self handleEvent:SGEventDisconnected payload:nil];
        return;
    }

    [[SGConfiguration sharedConfiguration] reloadFromDisk];
    [[SGDatabaseManager sharedManager] resetAllTokensToRequireUpload];

    RSA *privKey = SG_CryptoGetClientPrivateKey();
    if (!privKey) {
        SGLOGE(SGDaemon, "Freshly-written key failed to reload — wiping profile for re-registration.");
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

- (void)requestGracefulDisconnect {
    [self handleEvent:SGEventStopRequested payload:nil];
}

- (void)handleConfigurationReloadRequest {
    [[SGConfiguration sharedConfiguration] reloadFromDisk];
    [[SGDatabaseManager sharedManager] resetAllTokensToRequireUpload];
    [self reconcileTokensWithPlist];
    [self handleEvent:SGEventConfigReloaded payload:nil];

    /* Notify any control-channel subscriber so prefs UIs etc. can refresh. */
    if (_controlChannel) [_controlChannel postEvent:SGCEVT_CONFIG_RELOADED payload:nil];
}

- (void)handleSystemWake {
    [self handleEvent:SGEventSystemDidWake payload:nil];
}

- (void)performProfileWipeInline {
    @autoreleasepool {
        NSInteger profileIdx = [[SGConfiguration sharedConfiguration] activeProfileIndex];
        NSString *profilePath = SGPath([NSString stringWithFormat:
            @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile%ld.plist", (long)profileIdx]);
        NSMutableDictionary *profile = [NSMutableDictionary dictionaryWithContentsOfFile:profilePath] ?: [NSMutableDictionary dictionary];

        NSString *privKeyRelPath = profile[@"privateKey"];
        if (privKeyRelPath) {
            [[NSFileManager defaultManager] removeItemAtPath:SGPath(privKeyRelPath) error:nil];
        }

        [profile removeObjectForKey:@"device_address"];
        [profile removeObjectForKey:@"privateKey"];
        [profile writeToFile:profilePath atomically:YES];
        [[SGConfiguration sharedConfiguration] reloadFromDisk];
        [[SGDatabaseManager sharedManager] resetAllTokensToRequireUpload];
    }
}

#pragma mark - SpringBoard Push Delivery (via SGControlChannel)

/* Synchronous wrapper around the async channel send so callers retain their
 * KERN_SUCCESS-vs-other semantics. */
- (kern_return_t)_deliverPushTopic:(NSString *)topic payload:(NSDictionary *)payload {
    if (!_springBoardClient) {
        SGLOGW(SGDaemon, "Push delivery requested but no SpringBoard client attached.");
        return KERN_FAILURE;
    }
    if (!topic || [topic length] == 0) return KERN_INVALID_ARGUMENT;

    NSData *plistData = nil;
    if (payload) {
        plistData = [NSPropertyListSerialization dataWithPropertyList:payload
                                                               format:NSPropertyListBinaryFormat_v1_0
                                                              options:0
                                                                error:NULL];
    }
    if (!plistData) plistData = [NSData data];

    if ([plistData length] > SG_CONTROL_MAX_USERINFO_SIZE) {
        SGLOGE(SGDaemon, "Push payload too large for wire (%lu > %d).",
               (unsigned long)[plistData length], SG_CONTROL_MAX_USERINFO_SIZE);
        return KERN_RESOURCE_SHORTAGE;
    }

    SGCPushDeliveryPayload pd;
    memset(&pd, 0, sizeof(pd));
    strlcpy(pd.bundleID, [topic UTF8String], sizeof(pd.bundleID));
    pd.userInfoLength = (uint32_t)[plistData length];
    if (pd.userInfoLength > 0) memcpy(pd.userInfoData, [plistData bytes], pd.userInfoLength);

    NSUInteger sendLen = offsetof(SGCPushDeliveryPayload, userInfoData) + pd.userInfoLength;
    NSData *requestPayload = [NSData dataWithBytes:&pd length:sendLen];

    __block kern_return_t result = KERN_FAILURE;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    [_springBoardClient sendRequest:SGCMSG_PUSH_DELIVERY
                            payload:requestPayload
                            timeout:0
                         completion:^(SGControlError err, const SGControlChannelMessage *response) {
        result = (err == SGCERR_OK) ? KERN_SUCCESS : KERN_FAILURE;
        dispatch_semaphore_signal(sema);
    }];
    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
    dispatch_release(sema);

    return result;
}

#pragma mark - Notification Disposition Helpers

/* Call only after a definitive disposition; entries still pending local
 * redelivery are owned by the drain timer. */
- (void)_markMessageDeliveredID:(NSData *)msgID expiresAt:(int64_t)expiresAt {
    if (!msgID || [msgID length] == 0) return;
    [[SGDatabaseManager sharedManager] markMessageIDAsSeen:msgID expiresAt:expiresAt];
    @synchronized(_seenMessageIDs) {
        if (![_seenMessageIDs containsObject:msgID]) {
            [_seenMessageIDs addObject:msgID];
            if ([_seenMessageIDs count] > kSGSeenMessageIDCap) [_seenMessageIDs removeObjectAtIndex:0];
        }
    }
}

- (void)_advanceLastDeliveredSeqIfNeeded:(int64_t)arrivedSeq {
    if (arrivedSeq <= 0) return;
    SGDatabaseManager *db = [SGDatabaseManager sharedManager];
    int64_t currentMax = [db lastDeliveredSeq];
    if (arrivedSeq > currentMax) [db updateLastDeliveredSeq:arrivedSeq];
}

#pragma mark - Local Delivery Retry Queue

/* Safety-net only — primary drains are event-driven. Targets the drain queue
 * so the timer fire serialises with _kickLocalDeliveryDrain. */
- (void)_startLocalDeliveryRetryTimer {
    if (_localDeliveryRetryTimer) return;
    _localDeliveryRetryTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
        _localDeliveryDrainQueue);
    dispatch_source_set_timer(_localDeliveryRetryTimer,
                              dispatch_time(DISPATCH_TIME_NOW, kSGDrainSafetyIntervalSec * NSEC_PER_SEC),
                              kSGDrainSafetyIntervalSec * NSEC_PER_SEC,
                              kSGDrainSafetyLeewaySec * NSEC_PER_SEC);
    dispatch_source_set_event_handler(_localDeliveryRetryTimer, ^{
        [self _drainLocalPendingDeliveries];
    });
    dispatch_resume(_localDeliveryRetryTimer);
}

- (void)_stopLocalDeliveryRetryTimer {
    if (!_localDeliveryRetryTimer) return;
    dispatch_source_cancel(_localDeliveryRetryTimer);
    dispatch_release(_localDeliveryRetryTimer);
    _localDeliveryRetryTimer = NULL;
}

- (void)_kickLocalDeliveryDrain {
    dispatch_async(_localDeliveryDrainQueue, ^{
        [self _drainLocalPendingDeliveries];
    });
}

/* MUST run on _localDeliveryDrainQueue — call via _kickLocalDeliveryDrain or
 * the safety timer; direct invocation breaks the no-double-deliver invariant. */
- (void)_drainLocalPendingDeliveries {
    @autoreleasepool {
        SGDatabaseManager *db = [SGDatabaseManager sharedManager];
        NSArray *pending = [db allLocalPendingDeliveries];
        if ([pending count] == 0) return;

        int64_t now = (int64_t)time(NULL);
        for (NSDictionary *entry in pending) {
            @autoreleasepool {
                NSData   *msgID      = entry[@"msgID"];
                NSString *bundleID   = entry[@"bundleID"];
                NSData   *serialized = entry[@"payload"];
                int64_t   deviceSeq  = [entry[@"deviceSeq"] longLongValue];
                int64_t   expiresAt  = [entry[@"expiresAt"] longLongValue];

                if (now > expiresAt) {
                    SGLOGW(SGDaemon,
                           "Local-pending notification expired in retry queue (msg_id=%s) — ACKing EXPIRED.",
                           [[msgID description] UTF8String]);
                    SGP_EnqueueAcknowledgement(msgID, SGP_ACK_EXPIRED);
                    [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
                    [db removeLocalPendingDeliveryForMessageID:msgID];
                    continue;
                }

                /**
                 * propertyListFromData:mutabilityOption:format:errorDescription:
                 * is deprecated on modern iOS but available all the way back to
                 * iOS 2.0 — keep it for the iOS 3 floor.  -Wno-deprecated-declarations
                 * in the Makefile already silences the warning at build time.
                 */
                NSDictionary *parsed = (NSDictionary *)[NSPropertyListSerialization
                    propertyListFromData:serialized
                        mutabilityOption:NSPropertyListImmutable
                                  format:NULL
                        errorDescription:NULL];
                if (![parsed isKindOfClass:[NSDictionary class]]) {
                    SGLOGE(SGDaemon,
                           "Could not deserialize pending payload (msg_id=%s) — ACKing PARSE_FAILED.",
                           [[msgID description] UTF8String]);
                    SGP_EnqueueAcknowledgement(msgID, SGP_ACK_PARSE_FAILED);
                    [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
                    [db removeLocalPendingDeliveryForMessageID:msgID];
                    continue;
                }

                kern_return_t kr = [self _deliverPushTopic:bundleID payload:parsed];
                if (kr == KERN_SUCCESS) {
                    SGLOGI(SGDaemon,
                           "Local retry succeeded for msg_id=%s after earlier Mach failure.",
                           [[msgID description] UTF8String]);
                    SGP_EnqueueAcknowledgement(msgID, SGP_ACK_SUCCESS);
                    [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
                    [self _advanceLastDeliveredSeqIfNeeded:deviceSeq];
                    [db removeLocalPendingDeliveryForMessageID:msgID];
                }
                /* else: SpringBoard still unavailable — leave row for the next tick. */
            }
        }
    }
}

#pragma mark - Keepalive Algorithm Helpers

/**
 * Returns the current keepalive interval.
 * MUST be called while holding _stateLock.
 */
- (double)_currentKeepAliveInterval {
    return [[SGAvailability shared] currentIntervalForGrowthAlgorithm:_growthAlgorithm];
}

/**
 * Informs the algorithm of a keepalive result.
 * MUST be called while holding _stateLock.
 */
- (void)_processKeepAliveResult:(BOOL)success {
    [[SGAvailability shared] processResult:success forGrowthAlgorithm:_growthAlgorithm];
}

/**
 * Reinitializes the algorithm for a network type change.
 * MUST be called while holding _stateLock.
 */
- (void)_reinitializeKeepAliveForWiFi:(BOOL)isWiFi savedInterval:(double)savedInterval {
    [_growthAlgorithm release];
    _growthAlgorithm = [[SGAvailability shared]
        reinitializeGrowthAlgorithmForWiFi:isWiFi
                             savedInterval:savedInterval];
}

#pragma mark - PCPersistentTimer Keepalive (Survives Deep Sleep)

/**
 * Schedules a PCPersistentTimer for the current keepalive interval.
 * PCPersistentTimer internally registers with IOKit for power notifications
 * and schedules maintenance wakes via PCSystemWakeManager so the timer fires
 * even when the device is in deep sleep. This is the same mechanism apsd uses.
 *
 * The worker thread's select timeout remains as a redundant path — whichever
 * fires first sends the ping (dedup via _pingPendingSince in SGP_SendKeepAlivePing).
 *
 * Safe to call from any thread — dispatches to main internally.
 */
- (void)_scheduleKeepAliveTimer {
    if (![SGAvailability shared].persistentTimerAvailable) return;

    [_stateLock lock];
    double interval = [self _currentKeepAliveInterval];
    [_stateLock unlock];

    dispatch_async(dispatch_get_main_queue(), ^{
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

        [[SGAvailability shared] schedulePersistentTimer:self->_keepAliveTimer inRunLoop:[NSRunLoop mainRunLoop]];

        SGLOGI(SGDaemon, "PCPersistentTimer scheduled: %.0fs (survives sleep)", interval);
    });
}

/**
 * Invalidates and releases the current keepalive timer.
 * Safe to call from any thread — dispatches to main internally.
 */
- (void)_invalidateKeepAliveTimer {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self->_keepAliveTimer) {
            [self->_keepAliveTimer invalidate];
            [self->_keepAliveTimer release];
            self->_keepAliveTimer = nil;
        }
    });
}

/**
 * Fires on the main thread when the keepalive interval elapses.
 * During deep sleep, PCPersistentTimer schedules a maintenance wake,
 * the AP wakes briefly, this callback fires, ping goes out, pong
 * comes back, system sleeps again.
 */
- (void)_keepAliveTimerFired:(id)timer {
    if (!SGP_IsConnected()) {
        SGLOGD(SGDaemon, "PCPersistentTimer fired but not connected — ignoring.");
        return;
    }

    SGLOGD(SGDaemon, "PCPersistentTimer fired — sending keepalive ping.");
    BOOL sent = SGP_SendKeepAlivePing();

    if (sent) {
        [self _scheduleKeepAliveTimer];
    } else {
        /**
         * Ping already pending (worker thread beat us) or send failed.
         * Timer will be rescheduled in protocolDidReceiveKeepAlivePong
         * after the pong arrives and the adaptive algorithm updates.
         */
        SGLOGD(SGDaemon, "PCPersistentTimer: ping not sent (already pending or send failed).");
    }
}

- (void)performDNSResolution {
    NSString *address = [[SGConfiguration sharedConfiguration] serverAddress];
    if (!address) {
        [self handleEvent:SGEventDNSFailed payload:nil];
        return;
    }

    [_stateLock lock];
    uint32_t gen = _fsmGeneration;
    [_stateLock unlock];

    /**
     * Watchdog timer: if SGServerLocator blocks (mDNSResponder stall, DNS-SD socket
     * issue), kSGDNSWatchdogSec fires SGEventDNSFailed so the FSM backs off and
     * retries rather than blocking _entryActionQueue indefinitely. The generation
     * check inside scheduleTimerForEvent: discards the watchdog if DNS resolves first
     * (state changes → new generation → timer sees mismatch and no-ops).
     */
    [self scheduleTimerForEvent:SGEventDNSFailed delay:kSGDNSWatchdogSec generation:gen];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSDictionary *txt = [SGServerLocator resolveEndpointForServerAddress:address];

        /**
         * Discard the result if the FSM moved on while DNS was in flight
         * (e.g. network dropped, user disabled daemon, watchdog fired).
         */
        [self->_stateLock lock];
        BOOL isStale = (self->_fsmGeneration != gen);
        [self->_stateLock unlock];
        if (isStale) return;

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
        SGLOGE(SGDaemon, "Missing IP, Port, or Certificate. Aborting connection.");
        strlcpy(_lastErrorDetail, "Missing server IP, port, or certificate", sizeof(_lastErrorDetail));
        [self handleEvent:SGEventConnectFailed payload:nil];
        return;
    }

    [_stateLock lock];
    uint32_t gen = _fsmGeneration;
    [_stateLock unlock];

    /**
     * SGP_ConnectToServer performs a non-blocking TLS handshake and can
     * block for several seconds (TCP timeout, slow server). Running it on
     * the entry-action queue would serialize all subsequent state entry
     * actions behind the connect. Dispatching to the global queue keeps
     * the FSM responsive to concurrent events (network drop, SIGTERM).
     *
     * Pre-connect stale check: avoids starting a connection that will be
     * immediately discarded (e.g. network dropped just before we got here).
     *
     * Post-connect stale check: if the FSM transitioned while the TLS
     * handshake was in flight, close the socket we just opened so it is
     * not leaked. SGP_DisconnectFromServer (not SGP_AbortConnection) is
     * used here because SGP_ConnectToServer successfully completed the
     * handshake and the SSL/socket objects are in a valid state — a
     * graceful teardown avoids leaving the server slot in an ambiguous state.
     */
    NSString *ipCopy   = [ip copy];
    NSString *certCopy = [cert copy];
    int port = [portStr intValue];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            [self->_stateLock lock];
            BOOL isStale = (self->_fsmGeneration != gen);
            [self->_stateLock unlock];

            if (isStale) {
                [ipCopy release];
                [certCopy release];
                return;
            }

            int rc = SGP_ConnectToServer([ipCopy UTF8String], port, certCopy);

            [ipCopy release];
            [certCopy release];

            [self->_stateLock lock];
            isStale = (self->_fsmGeneration != gen);
            [self->_stateLock unlock];

            if (isStale) {
                if (rc == 0) {
                    /**
                     * Connection succeeded but FSM moved on — release the socket.
                     * Use Disconnect (not Abort) since the SSL object is valid.
                     */
                    SGP_DisconnectFromServer();
                }
                return;
            }

            if (rc == 0) {
                [self handleEvent:SGEventConnectSuccess payload:nil];
            } else {
                [self handleEvent:SGEventConnectFailed payload:nil];
            }
        }
    });
}

- (void)startConnectionScopedWorker {
    if (_workerActive) return;
    _workerActive = YES;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        SGLOGI(SGDaemon, "Connection worker started.");
        while (SGP_IsConnected()) {
            [self->_stateLock lock];
            double pingInterval = [self _currentKeepAliveInterval];
            [self->_stateLock unlock];
            
            int rc = SGP_ProcessNextIncomingMessage(pingInterval);
            
            if (rc != SGP_OK) {
                SGLOGI(SGDaemon, "Connection worker exited with code: %d", rc);
                if (rc == SGP_ERR_AUTH) {
                    [self handleEvent:SGEventAuthFailed payload:nil];
                } else {
                    [self handleEvent:SGEventDisconnected payload:nil];
                }
                break;
            }
        }
        dispatch_async(self->_entryActionQueue, ^{
            [self->_stateLock lock];
            self->_workerActive = NO;
            [self->_stateLock unlock];
        });
        SGLOGI(SGDaemon, "Connection worker stopped.");
    });
}

- (void)scheduleTimerForEvent:(SGEvent)event delay:(uint32_t)seconds generation:(uint32_t)generation {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, seconds * NSEC_PER_SEC), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self->_stateLock lock];
        BOOL isStale = (self->_fsmGeneration != generation);
        [self->_stateLock unlock];
        
        if (isStale) {
            SGLOGD(SGDaemon, "Timer (gen=%u) for event %ld expired but generation changed, discarding.", generation, (long)event);
            return;
        }
        [self handleEvent:event payload:nil];
    });
}

@end
