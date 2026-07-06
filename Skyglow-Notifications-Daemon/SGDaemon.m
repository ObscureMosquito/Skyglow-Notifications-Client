#import "SGDaemon.h"
#import "SGConfiguration.h"
#import "SGDatabaseManager.h"
#import "SGTokenManager.h"
#import "SGProtocolHandler.h"
#import "SGKeepAliveOffload.h"
#import "SGServerLocator.h"
#import "SGPayloadParser.h"
#import "SGCryptoEngine.h"
#import "SGAvailability.h"
#import "SGControlChannel.h"
#import "SGReachabilityMonitor.h"
#import "SGKeychainStore.h"
#import "SGStorage.h"
#import "SGLog.h"
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <libkern/OSAtomic.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/IOMessage.h>

static const int64_t       kSGDrainSafetyIntervalSec              = 300;
static const int64_t       kSGDrainSafetyLeewaySec                 =  30;
static const int64_t       kSGLocalPendingFallbackDeadlineSec      = 86400;
static const NSUInteger    kSGSeenMessageIDCap                     = 200;
static const NSTimeInterval kSGNotificationProcessingAssertionSec  = 15.0;
static NSString * const    kSGProfileCertificateDirectory          = @"/var/mobile/Library/SkyglowNotifications";

typedef struct { SGState from; SGState to; } SGTransition;

/* Per-state watchdog deadlines.  Each transient state gets one bound: if the
 * FSM has not advanced out of it within `seconds`, `onTimeout` is posted.  All
 * values derive from SGP_NET_OP_TIMEOUT_SEC (the transport socket timeout) so a
 * watchdog tracks the work it guards rather than being a guessed number:
 *   - single network op (DNS lookup, TCP+TLS connect): one op + scheduling slack
 *   - handshake (auth, register): two network legs (challenge then response)
 * BackingOff / IdleDNSFailed are deliberately absent: their delay is the
 * dynamic computed backoff, armed in the entry action, not a fixed deadline. */
typedef struct { SGState state; SGEvent onTimeout; uint32_t seconds; } SGStateDeadline;

static const SGStateDeadline kSGStateDeadlines[] = {
    { SGStateResolvingDNS,   SGEventDNSFailed,     SGP_NET_OP_TIMEOUT_SEC + 5 },
    { SGStateConnecting,     SGEventConnectFailed, SGP_NET_OP_TIMEOUT_SEC + 5 },
    { SGStateAuthenticating, SGEventAuthTimeout,   SGP_NET_OP_TIMEOUT_SEC * 2 },
    { SGStateRegistering,    SGEventDisconnected,  SGP_NET_OP_TIMEOUT_SEC * 2 },
};

static NSString *SGProfileCertificatePathForIndex(NSInteger profileIdx) {
    return [NSString stringWithFormat:@"%@/profile%ld-server.pem",
            kSGProfileCertificateDirectory, (long)profileIdx];
}

static BOOL SGPersistSharedPlist(NSDictionary *plist, NSString *path) {
    return SGAtomicWritePropertyList(plist, path, 0644, NULL);
}

static BOOL SGCertificatePEMLooksValid(NSString *pem) {
    if ([pem length] == 0) return NO;
    if ([pem rangeOfString:@"BEGIN CERTIFICATE"].location == NSNotFound) return NO;

    BIO *bio = BIO_new_mem_buf((void *)[pem UTF8String], (int)[pem lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
    if (!bio) return NO;
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cert) return NO;
    X509_free(cert);
    return YES;
}

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
    { SGStateResolvingDNS,      SGStateIdleUnregistered    },
    { SGStateResolvingDNS,      SGStateIdleNoNetwork       },
    { SGStateResolvingDNS,      SGStateDisabled            },

    { SGStateIdleDNSFailed,     SGStateResolvingDNS        },
    { SGStateIdleDNSFailed,     SGStateIdleUnregistered    },
    { SGStateIdleDNSFailed,     SGStateDisabled            },
    { SGStateIdleDNSFailed,     SGStateIdleNoNetwork       },

    { SGStateIdleNoNetwork,     SGStateConnecting          },
    { SGStateIdleNoNetwork,     SGStateIdleUnregistered    },
    { SGStateIdleNoNetwork,     SGStateDisabled            },
    { SGStateIdleNoNetwork,     SGStateResolvingDNS        },

    { SGStateIdleUnregistered,  SGStateResolvingDNS        },
    { SGStateIdleUnregistered,  SGStateDisabled            },

    { SGStateConnecting,        SGStateResolvingDNS        },
    { SGStateConnecting,        SGStateAuthenticating      },
    { SGStateConnecting,        SGStateRegistering         },
    { SGStateConnecting,        SGStateBackingOff          },
    { SGStateConnecting,        SGStateIdleNoNetwork       },
    { SGStateConnecting,        SGStateIdleUnregistered    },
    { SGStateConnecting,        SGStateIdleCircuitOpen     },
    { SGStateConnecting,        SGStateErrorBadConfig      },

    { SGStateRegistering,       SGStateAuthenticating      }, 
    { SGStateRegistering,       SGStateBackingOff          }, 
    { SGStateRegistering,       SGStateError               }, 
    { SGStateRegistering,       SGStateIdleNoNetwork       },
    { SGStateRegistering,       SGStateIdleUnregistered    },
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
    { SGStateConnected,         SGStateIdleUnregistered    },
    { SGStateConnected,         SGStateDisabled            },
    { SGStateConnected,         SGStateResolvingDNS        },

    { SGStateBackingOff,        SGStateConnecting          },
    { SGStateBackingOff,        SGStateResolvingDNS        },
    { SGStateBackingOff,        SGStateIdleNoNetwork       },
    { SGStateBackingOff,        SGStateIdleUnregistered    },
    { SGStateBackingOff,        SGStateIdleCircuitOpen     },
    { SGStateBackingOff,        SGStateDisabled            },

    { SGStateIdleCircuitOpen,   SGStateConnecting          },
    { SGStateIdleCircuitOpen,   SGStateIdleNoNetwork       },
    { SGStateIdleCircuitOpen,   SGStateIdleUnregistered    },
    { SGStateIdleCircuitOpen,   SGStateDisabled            },
    { SGStateIdleCircuitOpen,   SGStateResolvingDNS        },

    { SGStateErrorAuth,         SGStateDisabled            },
    { SGStateErrorAuth,         SGStateIdleUnregistered    },
    { SGStateErrorAuth,         SGStateResolvingDNS        },

    { SGStateErrorBadConfig,    SGStateDisabled            },
    { SGStateErrorBadConfig,    SGStateIdleUnregistered    },
    { SGStateErrorBadConfig,    SGStateResolvingDNS        },
    { SGStateAuthenticating,    SGStateErrorVersionMismatch },
    { SGStateRegistering,       SGStateErrorVersionMismatch },
    { SGStateConnected,         SGStateErrorVersionMismatch },
    { SGStateErrorVersionMismatch, SGStateDisabled          },
    { SGStateErrorVersionMismatch, SGStateIdleUnregistered  },
    { SGStateErrorVersionMismatch, SGStateResolvingDNS      },

    { SGStateError,             SGStateDisabled            },
    { SGStateError,             SGStateIdleUnregistered    },
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

static void SGCopyMessageIDHex(NSData *msgID, char *out, size_t outSize) {
    if (!out || outSize == 0) return;
    out[0] = '\0';
    if (!msgID || [msgID length] == 0) {
        strlcpy(out, "none", outSize);
        return;
    }

    const uint8_t *bytes = (const uint8_t *)[msgID bytes];
    NSUInteger len = MIN([msgID length], (NSUInteger)SGP_MSG_ID_LEN);
    size_t pos = 0;
    for (NSUInteger i = 0; i < len && pos + 2 < outSize; i++) {
        int written = snprintf(out + pos, outSize - pos, "%02x", bytes[i]);
        if (written != 2) break;
        pos += 2;
    }
    out[pos] = '\0';
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
    dispatch_queue_t       _storageQueue;
    SGControlChannel      *_controlChannel;
    SGControlChannel      *_springBoardClient;
    SGReachabilityMonitor *_reachability;
    io_connect_t           _powerRootPort;
    io_object_t            _powerNotifier;
    IONotificationPortRef  _powerNotifyPort;
}

- (id)init {
    if ((self = [super init])) {
        _stateLock           = [[NSLock alloc] init];
        _consecutiveFailures = 0;
        _fsmGeneration       = 0;
        _seenMessageIDs      = [[NSMutableOrderedSet alloc] initWithCapacity:kSGSeenMessageIDCap];
        _entryActionQueue    = dispatch_queue_create("com.skyglow.daemon.entry", DISPATCH_QUEUE_SERIAL);
        _localDeliveryDrainQueue = dispatch_queue_create("com.skyglow.daemon.drain", DISPATCH_QUEUE_SERIAL);
        _storageQueue = dispatch_queue_create("com.skyglow.daemon.storage", DISPATCH_QUEUE_SERIAL);
        _powerRootPort       = MACH_PORT_NULL;
        _powerNotifier       = MACH_PORT_NULL;
        _powerNotifyPort     = NULL;
    }
    return self;
}

- (void)dealloc {
    [_stateLock release];
    [_seenMessageIDs release];
    [_growthAlgorithm release];
    [_controlChannel release];
    [_springBoardClient release];
    [_reachability stopMonitoringSystemNetworkChanges];
    [_reachability release];
    [self _stopPowerMonitoring];
    if (_keepAliveTimer) { [_keepAliveTimer invalidate]; [_keepAliveTimer release]; }
    [self _stopLocalDeliveryRetryTimer];
    dispatch_release(_entryActionQueue);
    if (_localDeliveryDrainQueue) dispatch_release(_localDeliveryDrainQueue);
    if (_storageQueue) dispatch_release(_storageQueue);
    [super dealloc];
}

- (void)attachControlChannel:(SGControlChannel *)channel {
    if (channel == _controlChannel) return;
    [channel retain];
    [_controlChannel release];
    _controlChannel = channel;
}

- (SGControlChannel *)springBoardClient {
    return _springBoardClient;
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
    if ([[SGConfiguration sharedConfiguration] isEnabled]) {
        [self _enterActiveMode];
    } else {
        /* Disabled stops network activity, not storage maintenance. In
         * particular, a legacy pendingDeletions fallback from SpringBoard
         * still has to be consumed after a disabled daemon restarts. */
        [self reconcileTokensWithPlist];
    }

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

    [self _kickLocalDeliveryDrain];
    [self _startReachabilityMonitor];
    [self _startPowerMonitoring];
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
    dispatch_async(_localDeliveryDrainQueue, ^{
        [self _stopLocalDeliveryRetryTimer];
    });
    [self _stopReachabilityMonitor];
    [self _stopPowerMonitoring];
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

- (void)_stopReachabilityMonitor {
    if (!_reachability) return;
    [_reachability stopMonitoringSystemNetworkChanges];
    [_reachability release];
    _reachability = nil;
}

#pragma mark - IOKit Power Monitoring

static void SG_IOPowerCallback(void *refcon, io_service_t service,
                                natural_t messageType, void *messageArgument) {
    SGDaemon *daemon = (__bridge SGDaemon *)refcon;
    switch (messageType) {
        case kIOMessageSystemHasPoweredOn:
            [daemon handleSystemWake];
            break;
        case kIOMessageSystemWillSleep:
            [daemon _armScheduledWakeIfNeeded];
            IOAllowPowerChange(daemon->_powerRootPort, (long)messageArgument);
            break;
        case kIOMessageCanSystemSleep:
            IOAllowPowerChange(daemon->_powerRootPort, (long)messageArgument);
            break;
        default:
            break;
    }
}

- (void)_startPowerMonitoring {
    if (_powerRootPort != MACH_PORT_NULL) return;
    _powerRootPort = IORegisterForSystemPower((__bridge void *)self,
                                              &_powerNotifyPort,
                                              SG_IOPowerCallback,
                                              &_powerNotifier);
    if (_powerRootPort == MACH_PORT_NULL) {
        SGLOGW(SGDaemon, "code=%s result=disabled reason=iokit_registration_failed", SGND_AVAILABILITY_POWER_NOTIFY_FAILED);
        return;
    }
    CFRunLoopAddSource(CFRunLoopGetMain(),
                       IONotificationPortGetRunLoopSource(_powerNotifyPort),
                       kCFRunLoopDefaultMode);
    SGLOGI(SGDaemon, "code=%s result=registered", SGND_AVAILABILITY_POWER_NOTIFY_READY);
}

- (void)_stopPowerMonitoring {
    if (_powerRootPort == MACH_PORT_NULL) return;
    if (_powerNotifier != MACH_PORT_NULL) {
        IODeregisterForSystemPower(&_powerNotifier);
        _powerNotifier = MACH_PORT_NULL;
    }
    IOServiceClose(_powerRootPort);
    _powerRootPort = MACH_PORT_NULL;
    if (_powerNotifyPort) {
        IONotificationPortDestroy(_powerNotifyPort);
        _powerNotifyPort = NULL;
    }
}

- (BOOL)_runDeletionCascadeForBundle:(NSString *)bundleID {
    if (![bundleID length]) return NO;
    return [[SGDatabaseManager sharedManager]
        removeAllStateForBundleIdentifier:bundleID];
}

- (void)reconcileTokensWithPlist {
    NSString *plistPath = SGPath(SG_PREFS_PLIST_PATH);
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    NSDictionary *appStatus = [prefs objectForKey:@"appStatus"] ?: @{};
    SGDatabaseManager *db = [SGDatabaseManager sharedManager];

    NSArray *pending = [prefs objectForKey:@"pendingDeletions"] ?: @[];
    if ([pending count] > 0) {
        NSMutableArray *completed = [NSMutableArray array];
        for (NSString *bundleID in pending) {
            if ([self _runDeletionCascadeForBundle:bundleID]) {
                [completed addObject:bundleID];
                SGLOGI(SGDaemon,
                       "code=%s bundle=%s action=recover_pending_deletion",
                       SGND_DAEMON_PENDING_DELETION_RECOVERED,
                       [bundleID UTF8String]);
            } else {
                SGLOGE(SGDaemon,
                       "code=%s bundle=%s action=retain_pending_deletion",
                       SGND_DAEMON_PENDING_DELETION_FAILED,
                       [bundleID UTF8String]);
            }
        }
        if ([completed count] > 0) {
            [self _clearPendingDeletionsInPlistForBundles:completed];
        }
    }

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
    BOOL mutated = ([pending count] > 0);
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
        [self schedulePublicStateSnapshot];
    }
}

- (void)handleEvent:(SGEvent)event payload:(id)payload {
    [_stateLock lock];
    
    SGStatusPayload currentStatus;
    SGStatusServer_Current(&currentStatus);
    SGState currentState = (SGState)currentStatus.state;
    
    SGLOGD(SGDaemon, "code=%s event=%ld state=%s", SGND_FSM_EVENT, (long)event, SGState_GetName(currentState));

    if (event == SGEventStopRequested ||
       (event == SGEventConfigReloaded && ![[SGConfiguration sharedConfiguration] isEnabled])) {
        _consecutiveFailures = 0;
        strlcpy(_lastErrorDetail, "Daemon is disabled", sizeof(_lastErrorDetail));
        [self executeTransitionToState:SGStateDisabled backoff:0 ip:NULL];
        [_stateLock unlock];
        return;
    }

    if (event == SGEventNetworkDown) {
        if (currentState != SGStateDisabled &&
            currentState != SGStateErrorBadConfig &&
            currentState != SGStateErrorVersionMismatch) {
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

    /* Every handled arm below drives a transition, which bumps _fsmGeneration.
     * If the generation is unchanged after dispatch the event was a no-op in
     * this state, surface it instead of letting it vanish silently.  Arms
     * that intentionally act without transitioning set the flag instead. */
    uint32_t genBeforeDispatch = _fsmGeneration;
    BOOL handledWithoutTransition = NO;

    switch (currentState) {
        case SGStateStarting:
        case SGStateDisabled:
        case SGStateErrorBadConfig:
        case SGStateErrorVersionMismatch:
        case SGStateIdleUnregistered:
            if (event == SGEventStartRequested || event == SGEventConfigReloaded) {
                _consecutiveFailures = 0;
                if (![[SGConfiguration sharedConfiguration] isEnabled]) {
                    strlcpy(_lastErrorDetail, "Daemon is disabled", sizeof(_lastErrorDetail));
                    [self executeTransitionToState:SGStateDisabled backoff:0 ip:NULL];
                } else if ([[SGConfiguration sharedConfiguration] isValid]) {
                    _lastErrorDetail[0] = '\0';
                    [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
                } else if (![[SGConfiguration sharedConfiguration] hasProfile]) {
                    strlcpy(_lastErrorDetail, "No profile configured", sizeof(_lastErrorDetail));
                    [self executeTransitionToState:SGStateIdleUnregistered backoff:0 ip:NULL];
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
                SGLOGI(SGDaemon, "code=%s state=BackingOff action=retry_now", SGND_WAKE_BACKOFF_RESET);
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

        case SGStateRegistering:
            if (event == SGEventConfigReloaded) {
                _consecutiveFailures = 0;
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            } else if (event == SGEventAuthFailed) {
                /* Wire registration succeeded but the device address / private
                 * key could not be persisted (e.g. keychain write or reload
                 * failed).  The half-registered profile is useless — wipe it and
                 * back off rather than waiting for the registration watchdog. */
                strlcpy(_lastErrorDetail, "Registration succeeded but key could not be stored", sizeof(_lastErrorDetail));
                [self performProfileWipeInline];
                [self executeFailureBackoff];
            } else if (event == SGEventDisconnected) {
                strlcpy(_lastErrorDetail, "Disconnected during registration", sizeof(_lastErrorDetail));
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
            } else if (event == SGEventSystemDidWake || event == SGEventNetworkUp) {
                SGLOGI(SGDaemon, "code=%s trigger=%s action=probe_liveness", SGND_KEEPALIVE_PROBE,
                       (event == SGEventSystemDidWake) ? "system_wake" : "network_change");
                [self _probeConnectionLiveness];
                handledWithoutTransition = YES;
            }
            break;
            
        case SGStateErrorAuth:
            if (event == SGEventConfigReloaded) {
                _consecutiveFailures = 0;
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            }
            break;

        case SGStateIdleCircuitOpen:
            if (event == SGEventNetworkUp || event == SGEventConfigReloaded) {
                _consecutiveFailures = 0;
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            } else if (event == SGEventSystemDidWake) {
                SGLOGI(SGDaemon, "code=%s state=IdleCircuitOpen action=reset_failures", SGND_WAKE_CIRCUIT_RESET);
                _consecutiveFailures = 0;
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
    if (!isLegalTransition((SGState)current.state, newState) && current.state != newState) {
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
    [self schedulePublicStateSnapshot];
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

    BOOL leavingDisabled = (current.state == SGStateDisabled && newState != SGStateDisabled);
    BOOL enteringDisabled = (current.state != SGStateDisabled && newState == SGStateDisabled);

    dispatch_async(_entryActionQueue, ^{
        [self->_stateLock lock];
        BOOL isStale = (self->_fsmGeneration != capturedGen);
        [self->_stateLock unlock];
        if (isStale) return;

        [self _invalidateKeepAliveTimer];

        if (leavingDisabled) {
            [self _enterActiveMode];
        }

        switch (newState) {
            case SGStateResolvingDNS: {
                SGP_AbortConnection();
                /* If this profile has no identity yet it will have to register,
                 * which needs a fresh RSA-2048 keypair.  Kick keygen now so it
                 * overlaps DNS + TLS instead of stalling the connection worker
                 * (and the disable signal) once S_HELLO arrives. */
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
            /* SGStateRegistering has no entry action of its own — its watchdog,
             * like every transient state's, is armed from the deadline table. */
            case SGStateConnected:
                [self _scheduleKeepAliveTimer];
                break;
            case SGStateBackingOff:
            case SGStateIdleDNSFailed:
                SGP_AbortConnection();
                [self scheduleTimerForEvent:SGEventBackoffTimerFired delay:backoff generation:capturedGen];
                break;
            case SGStateIdleCircuitOpen:
                SGP_AbortConnection();
                break;
            case SGStateDisabled:
            case SGStateIdleNoNetwork:
            case SGStateErrorBadConfig:
            case SGStateErrorVersionMismatch:
            case SGStateErrorAuth:
                SGP_AbortConnection();
                break;
            default:
                break;
        }

        if (enteringDisabled) {
            [self _exitActiveMode];
        }
    });

    /* Arm this state's watchdog from the unified deadline table.  States with a
     * dynamic delay (BackingOff / IdleDNSFailed) arm their own timer in the
     * entry action above and are intentionally not in the table. */
    [self armWatchdogForState:newState generation:capturedGen];
}

- (void)armWatchdogForState:(SGState)state generation:(uint32_t)generation {
    for (size_t i = 0; i < sizeof(kSGStateDeadlines) / sizeof(kSGStateDeadlines[0]); i++) {
        if (kSGStateDeadlines[i].state == state) {
            [self scheduleTimerForEvent:kSGStateDeadlines[i].onTimeout
                                  delay:kSGStateDeadlines[i].seconds
                             generation:generation];
            return;
        }
    }
}

- (void)executeFailureBackoff {
    _consecutiveFailures++;
    
    if (_consecutiveFailures >= SG_MAX_CONSECUTIVE_FAILURES) {
        SGLOGW(SGDaemon, "code=%s failures=%d action=idle_until_network_change", SGND_BACKOFF_CIRCUIT_OPEN, SG_MAX_CONSECUTIVE_FAILURES);
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
            SGLOGI(SGDaemon, "code=%s retry_after=%u action=honor", SGND_BACKOFF_RETRY_AFTER, serverHint);
        }

        SGLOGI(SGDaemon, "code=%s delay=%u failure=%d max=%d", SGND_BACKOFF_SCHEDULED,
                    finalDelay, _consecutiveFailures, SG_MAX_CONSECUTIVE_FAILURES);
        [self executeTransitionToState:SGStateBackingOff backoff:finalDelay ip:NULL];
    }
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
    [self _kickLocalDeliveryDrain];
}

- (void)_attemptKeepAliveOffload {
    [_stateLock lock];
    double interval = [self _currentKeepAliveInterval];
    [_stateLock unlock];
    SGKAOffload_TryEnable(interval);
}

- (void)protocolDidReceiveNotification:(NSDictionary *)messageDict {
    @autoreleasepool {
        NSData *msgID = messageDict[@"msg_id"];
        if (!msgID || [msgID length] != SGP_MSG_ID_LEN) return;

        char msgHex[SGP_MSG_ID_LEN * 2 + 1];
        SGCopyMessageIDHex(msgID, msgHex, sizeof(msgHex));

        SGDatabaseManager *db = [SGDatabaseManager sharedManager];

        if ([db hasSeenMessageID:msgID]) {
            SGLOGD(SGDaemon, "code=%s msg=%s ack=success action=redeliver_ack_only", SGND_DELIVERY_DUPLICATE, msgHex);
            SGP_EnqueueAcknowledgement(msgID, SGP_ACK_SUCCESS);
            return;
        }
        if ([db hasLocalPendingDeliveryForMessageID:msgID]) {
            SGLOGD(SGDaemon, "code=%s msg=%s action=ignore_pending_retry", SGND_DELIVERY_LOCAL_PENDING_DUPLICATE, msgHex);
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
            SGLOGI(SGDaemon, "code=%s msg=%s age=%llds expires_at=%lld now=%lld ack=expired", SGND_DELIVERY_EXPIRED,
                        msgHex, now - expiresAt, expiresAt, now);
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
            SGLOGW(SGDaemon, "code=%s msg=%s action=drop reason=routing_key_missing", SGND_DELIVERY_ROUTING_MISSING, msgHex);
            goto cleanup_assertion;
        }

        if ([db isMutedForRoutingKey:routingKey]) {
            SGLOGI(SGDaemon, "code=%s msg=%s bundle=%s ack=success action=suppress", SGND_DELIVERY_MUTED,
                        msgHex, [routingData[@"bundleID"] UTF8String]);
            SGP_EnqueueAcknowledgement(msgID, SGP_ACK_SUCCESS);
            [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
            goto cleanup_assertion;
        }

        NSData *payloadBytes = messageDict[@"data"];
        if (!payloadBytes) {
            SGLOGW(SGDaemon, "code=%s msg=%s ack=parse_failed action=drop", SGND_DELIVERY_PAYLOAD_EMPTY, msgHex);
            SGP_EnqueueAcknowledgement(msgID, SGP_ACK_PARSE_FAILED);
            [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
            goto cleanup_assertion;
        }

        SGLOGI(SGDaemon, "code=%s msg=%s bundle=%s encrypted=%s bytes=%lu result=received", SGND_DELIVERY_RECEIVED,
                    msgHex, [routingData[@"bundleID"] UTF8String],
                    [messageDict[@"is_encrypted"] boolValue] ? "yes" : "no",
                    (unsigned long)[payloadBytes length]);

        if ([messageDict[@"is_encrypted"] boolValue]) {
            SGLOGD(SGDaemon, "code=%s msg=%s bytes=%lu action=decrypt", SGND_DELIVERY_PAYLOAD_ENCRYPTED,
                        msgHex, (unsigned long)[payloadBytes length]);
            if ([payloadBytes length] < SGP_GCM_TAG_LEN) {
                SGLOGW(SGDaemon, "code=%s msg=%s bytes=%lu min=%d ack=decrypt_failed action=drop", SGND_DELIVERY_CIPHERTEXT_SHORT,
                            msgHex, (unsigned long)[payloadBytes length], SGP_GCM_TAG_LEN);
                SGP_EnqueueAcknowledgement(msgID, SGP_ACK_DECRYPT_FAILED);
                [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
                goto cleanup_assertion;
            }
            NSData *iv = messageDict[@"iv"];
            if (!iv) {
                SGLOGW(SGDaemon, "code=%s msg=%s ack=decrypt_failed action=drop", SGND_DELIVERY_IV_MISSING, msgHex);
                SGP_EnqueueAcknowledgement(msgID, SGP_ACK_DECRYPT_FAILED);
                [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
                goto cleanup_assertion;
            }

            payloadBytes = SG_CryptoDecryptAESGCM(payloadBytes, routingData[@"e2eeKey"], iv, nil);
            if (!payloadBytes) {
                SGLOGE(SGDaemon, "code=%s msg=%s ack=decrypt_failed action=drop", SGND_DELIVERY_DECRYPT_FAILED, msgHex);
                SGP_EnqueueAcknowledgement(msgID, SGP_ACK_DECRYPT_FAILED);
                [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
                goto cleanup_assertion;
            }
        } else {
            SGLOGD(SGDaemon, "code=%s msg=%s bytes=%lu", SGND_DELIVERY_PAYLOAD_PLAINTEXT, msgHex, (unsigned long)[payloadBytes length]);
        }

        /* Decompress AFTER decrypt (the server compresses then encrypts). The
         * flag is independent of content_type, so it covers JSON/plist/TLV alike. */
        if ([messageDict[@"is_compressed"] boolValue]) {
            NSData *inflated = SG_PayloadInflate((const uint8_t *)payloadBytes.bytes,
                                                 (uint32_t)payloadBytes.length,
                                                 SGP_MAX_INFLATED_LEN);
            if (!inflated) {
                SGLOGW(SGDaemon, "code=%s msg=%s bytes=%lu ack=parse_failed action=drop", SGND_DELIVERY_INFLATE_FAILED,
                            msgHex, (unsigned long)[payloadBytes length]);
                SGP_EnqueueAcknowledgement(msgID, SGP_ACK_PARSE_FAILED);
                [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
                goto cleanup_assertion;
            }
            SGLOGD(SGDaemon, "code=%s msg=%s in=%lu out=%lu action=inflate", SGND_DELIVERY_PAYLOAD_INFLATED,
                        msgHex, (unsigned long)[payloadBytes length], (unsigned long)[inflated length]);
            payloadBytes = inflated;
        }

        uint8_t contentType = (uint8_t)[messageDict[@"content_type"] unsignedCharValue];
        NSDictionary *parsed = SG_PayloadDecode((const uint8_t *)payloadBytes.bytes, (uint32_t)payloadBytes.length, contentType);
        if (!parsed || parsed.count == 0) {
            SGLOGW(SGDaemon, "code=%s msg=%s bytes=%lu fmt=%u ack=parse_failed action=drop", SGND_DELIVERY_PARSE_FAILED,
                        msgHex, (unsigned long)[payloadBytes length], (unsigned)contentType);
            SGP_EnqueueAcknowledgement(msgID, SGP_ACK_PARSE_FAILED);
            [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
            goto cleanup_assertion;
        }

        SGLOGI(SGDaemon, "code=%s msg=%s bundle=%s keys=%lu action=send_to_springboard", SGND_DELIVERY_DISPATCHING,
                    msgHex, [routingData[@"bundleID"] UTF8String], (unsigned long)[parsed count]);

        NSNumber *seqNum = messageDict[@"device_seq"];
        int64_t arrivedSeq = seqNum ? [seqNum longLongValue] : 0;

        kern_return_t deliveryKr = [self _deliverPushTopic:routingData[@"bundleID"] payload:parsed];
        if (deliveryKr == KERN_SUCCESS) {
            SGP_EnqueueAcknowledgement(msgID, SGP_ACK_SUCCESS);
            [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
            [self _advanceLastDeliveredSeqIfNeeded:arrivedSeq];

            [self _kickLocalDeliveryDrain];
        } else {
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
                dispatch_async(_localDeliveryDrainQueue, ^{
                    [self _startLocalDeliveryRetryTimer];
                });
                SGLOGW(SGDaemon, "code=%s msg=%s bundle=%s kr=%d deadline=%s action=queue_local_retry", SGND_DELIVERY_LOCAL_RETRY_QUEUED,
                            msgHex, [routingData[@"bundleID"] UTF8String], deliveryKr,
                            (expiresAt > now) ? "wire_expiry" : "fallback");
            } else {
                SGLOGE(SGDaemon, "code=%s msg=%s kr=%d ack=parse_failed action=halt_resends", SGND_DELIVERY_LOCAL_RETRY_BAD_PAYLOAD, msgHex, deliveryKr);
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

- (void)protocolDidCompleteRegistrationWithAddress:(NSString *)deviceAddress privateKey:(char *)pemKey serverVersion:(uint32_t)serverVersion {

    if (!pemKey) {
        [self handleEvent:SGEventDisconnected payload:nil];
        return;
    }

    size_t pemLen = strlen(pemKey);

    NSInteger profileIdx = [[SGConfiguration sharedConfiguration] activeProfileIndex];
    NSString *profilePath = SGPath([NSString stringWithFormat:
        SG_PROFILE_PLIST_FORMAT, (long)profileIdx]);
    NSMutableDictionary *profile = [NSMutableDictionary dictionaryWithContentsOfFile:profilePath] ?: [NSMutableDictionary dictionary];

    profile[@"device_address"] = deviceAddress;

    NSString *pemString = [[NSString alloc] initWithBytes:pemKey
                                                   length:pemLen
                                                 encoding:NSUTF8StringEncoding];
    SGP_ZeroAndFreeKeyMaterial(pemKey, pemLen);
    pemKey = NULL;

    BOOL keyStored = SGKeychain_StorePrivateKeyPEM(pemString, profileIdx);
    [pemString release];

    if (!keyStored) {
        SGLOGE(SGDaemon, "code=%s profile=%ld result=failed", SGND_REGISTRATION_KEY_WRITE_FAILED, (long)profileIdx);
        [self handleEvent:SGEventDisconnected payload:nil];
        return;
    }

    if (!SGPersistSharedPlist(profile, profilePath)) {
        SGKeychain_DeletePrivateKey(profileIdx);
        [self handleEvent:SGEventDisconnected payload:nil];
        return;
    }

    [[SGConfiguration sharedConfiguration] reloadFromDisk];

    [self reconcileTokensWithPlist];

    RSA *privKey = SG_CryptoGetClientPrivateKey();
    if (!privKey) {
        SGLOGE(SGDaemon, "code=%s profile=%ld action=wipe_profile", SGND_REGISTRATION_KEY_RELOAD_FAILED, (long)profileIdx);
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
    [self reconcileTokensWithPlist];
    [self handleEvent:SGEventConfigReloaded payload:nil];
    [self drainDurableEventInbox];
    [self schedulePublicStateSnapshot];

    if (_controlChannel) [_controlChannel postEvent:SGCEVT_CONFIG_RELOADED payload:nil];
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

- (void)dispatchResetRegistrationForBundleIdentifier:(NSString *)bundleID
                                          completion:(void (^)(SGControlError err))completion {
    if (![bundleID length]) {
        if (completion) completion(SGCERR_INVALID_REQUEST);
        return;
    }
    if (!_springBoardClient) {
        if (completion) completion(SGCERR_UNREACHABLE);
        return;
    }

    SGCBundleIdPayload payload;
    memset(&payload, 0, sizeof(payload));
    strlcpy(payload.bundleID, [bundleID UTF8String], sizeof(payload.bundleID));
    NSData *data = [NSData dataWithBytes:&payload length:sizeof(payload)];

    [_springBoardClient sendRequest:SGCMSG_RESET_APP_REGISTRATION
                            payload:data
                            timeout:0
                         completion:^(SGControlError err, const SGControlChannelMessage *response) {
        (void)response;
        if (completion) completion(err);
    }];
}

- (BOOL)_updateMainPreferences:
    (void (^)(NSMutableDictionary *preferences))mutation {
    if (!mutation) return NO;
    @synchronized(self) {
        NSString *plistPath = SGPath(SG_PREFS_PLIST_PATH);
        NSMutableDictionary *preferences =
            [NSMutableDictionary dictionaryWithContentsOfFile:plistPath]
            ?: [NSMutableDictionary dictionary];
        mutation(preferences);
        return SGPersistSharedPlist(preferences, plistPath);
    }
}

- (BOOL)clearPendingDeletionForBundleIdentifier:(NSString *)bundleID {
    if (![bundleID length]) return NO;
    return [self _clearPendingDeletionsInPlistForBundles:@[bundleID]];
}

- (BOOL)_clearPendingDeletionsInPlistForBundles:(NSArray *)bundles {
    if ([bundles count] == 0) return YES;
    return [self _updateMainPreferences:^(NSMutableDictionary *preferences) {
        NSArray *current = [preferences objectForKey:@"pendingDeletions"];
        if ([current count] == 0) return;
        NSMutableArray *next = [NSMutableArray arrayWithArray:current];
        [next removeObjectsInArray:bundles];
        [preferences setObject:next forKey:@"pendingDeletions"];
    }];
}

- (BOOL)performSetEnabled:(BOOL)enabled {
    BOOL persisted = [self _updateMainPreferences:^(NSMutableDictionary *preferences) {
        [preferences setObject:[NSNumber numberWithBool:enabled]
                        forKey:@"enabled"];
    }];
    if (!persisted) return NO;

    /* Same reload path RELOAD_CONFIG uses: re-read config and drive the FSM so
     * the enable/disable takes effect immediately (connect or tear down). */
    [self handleConfigurationReloadRequest];
    [self schedulePublicStateSnapshot];
    return YES;
}

- (BOOL)persistAppEnabled:(BOOL)enabled forBundleIdentifier:(NSString *)bundleID {
    if (![bundleID length]) return NO;
    return [self _updateMainPreferences:^(NSMutableDictionary *preferences) {
        NSMutableDictionary *appStatus =
            [NSMutableDictionary dictionaryWithDictionary:
                [preferences objectForKey:@"appStatus"] ?: @{}];
        [appStatus setObject:[NSNumber numberWithBool:enabled] forKey:bundleID];
        [preferences setObject:appStatus forKey:@"appStatus"];
    }];
}

- (BOOL)removeAppStatusForBundleIdentifier:(NSString *)bundleID {
    if (![bundleID length]) return NO;
    return [self _updateMainPreferences:^(NSMutableDictionary *preferences) {
        NSMutableDictionary *appStatus =
            [NSMutableDictionary dictionaryWithDictionary:
                [preferences objectForKey:@"appStatus"] ?: @{}];
        [appStatus removeObjectForKey:bundleID];
        [preferences setObject:appStatus forKey:@"appStatus"];
    }];
}

- (BOOL)performSetAppEnabled:(BOOL)enabled
         forBundleIdentifier:(NSString *)bundleID {
    if (!SG_IsIdentifierStringSafe(bundleID)) return NO;

    @synchronized(self) {
        SGDatabaseManager *database = [SGDatabaseManager sharedManager];
        if (!database) return NO;

        NSDictionary *preferences = [NSDictionary dictionaryWithContentsOfFile:
            SGPath(SG_PREFS_PLIST_PATH)] ?: @{};
        id previousIntent =
            [[preferences objectForKey:@"appStatus"] objectForKey:bundleID];
        /* No persisted provider choice is fail-closed. Otherwise appStatus's
         * boolean is the durable source for the pre-request mute state. */
        BOOL rollbackMuted =
            previousIntent ? ![previousIntent boolValue] : YES;

        if (enabled) {
            SGTokenManager *tokenManager = [[SGTokenManager alloc] init];
            NSError *tokenError = nil;
            NSData *token = [tokenManager
                synchronizedTokenForBundleIdentifier:bundleID
                                               error:&tokenError];
            [tokenManager release];
            if (!token) {
                SGLOGE(SGDaemon,
                       "code=%s bundle=%s result=failed reason=%s",
                       SGND_TOKEN_GENERATE_FAILED, [bundleID UTF8String],
                       [[tokenError description] UTF8String]);
                return NO;
            }
        }

        BOOL databaseUpdated =
            [database setMuted:!enabled forBundleIdentifier:bundleID];
        BOOL intentUpdated =
            databaseUpdated &&
            [self persistAppEnabled:enabled forBundleIdentifier:bundleID];
        if (!intentUpdated) {
            [database setMuted:rollbackMuted forBundleIdentifier:bundleID];
            return NO;
        }

        SGP_FlushActiveTopicFilter();
        [self schedulePublicStateSnapshot];
        return YES;
    }
}

- (BOOL)performClearAppIntentForBundleIdentifier:(NSString *)bundleID {
    if (!SG_IsIdentifierStringSafe(bundleID)) return NO;
    BOOL removed = [self removeAppStatusForBundleIdentifier:bundleID];
    if (removed) [self schedulePublicStateSnapshot];
    return removed;
}

- (BOOL)performDeleteAppStateForBundleIdentifier:(NSString *)bundleID {
    if (!SG_IsIdentifierStringSafe(bundleID)) return NO;
    @synchronized(self) {
        BOOL databaseClean = [self _runDeletionCascadeForBundle:bundleID];
        BOOL pendingCleared =
            [self clearPendingDeletionForBundleIdentifier:bundleID];
        BOOL intentRemoved =
            [self removeAppStatusForBundleIdentifier:bundleID];
        if (!(databaseClean && pendingCleared && intentRemoved)) return NO;

        SGP_FlushActiveTopicFilter();
        [self schedulePublicStateSnapshot];
        return YES;
    }
}

- (BOOL)performSetStatusBarIndicatorEnabled:(BOOL)enabled {
    BOOL persisted = [self _updateMainPreferences:
        ^(NSMutableDictionary *preferences) {
            [preferences setObject:[NSNumber numberWithBool:enabled]
                            forKey:@"statusBarIndicatorEnabled"];
        }];
    if (!persisted) return NO;
    if (_controlChannel) {
        [_controlChannel postEvent:SGCEVT_CONFIG_RELOADED payload:nil];
    }
    [self schedulePublicStateSnapshot];
    return YES;
}

- (BOOL)_writePublicStateSnapshot {
    NSDictionary *preferences = [NSDictionary dictionaryWithContentsOfFile:
        SGPath(SG_PREFS_PLIST_PATH)] ?: @{};
    NSDictionary *previous = [NSDictionary dictionaryWithContentsOfFile:
        SGPath(SG_PUBLIC_STATE_PATH)];
    unsigned long long generation =
        [[previous objectForKey:@"generation"] unsignedLongLongValue] + 1;

    NSMutableDictionary *snapshot = [NSMutableDictionary dictionary];
    [snapshot setObject:[NSNumber numberWithInteger:1] forKey:@"formatVersion"];
    [snapshot setObject:[NSNumber numberWithUnsignedLongLong:generation]
                 forKey:@"generation"];
    [snapshot setObject:[NSNumber numberWithDouble:
        ([[NSDate date] timeIntervalSince1970])] forKey:@"updatedAt"];

    for (NSString *key in @[
            @"enabled", @"activeProfile", @"logLevel",
            @"statusBarIndicatorEnabled", @"appStatus"]) {
        id value = [preferences objectForKey:key];
        if (value) [snapshot setObject:value forKey:key];
    }

    NSArray *registered = [[[[SGDatabaseManager sharedManager]
        registeredBundleIdentifiers] allObjects]
        sortedArrayUsingSelector:@selector(compare:)];
    [snapshot setObject:registered ?: @[] forKey:@"registeredBundleIDs"];

    SGStatusPayload status;
    memset(&status, 0, sizeof(status));
    SGStatusServer_Current(&status);
    NSString *serverIP = [NSString stringWithUTF8String:status.serverIP] ?: @"";
    NSString *errorDetail =
        [NSString stringWithUTF8String:status.errorDetail] ?: @"";
    NSDictionary *statusDictionary = @{
        @"state": [NSNumber numberWithUnsignedInt:status.state],
        @"consecutiveFailures":
            [NSNumber numberWithUnsignedInt:status.consecutiveFailures],
        @"currentBackoffSec":
            [NSNumber numberWithUnsignedInt:status.currentBackoffSec],
        @"serverIP": serverIP,
        @"daemonStartTime":
            [NSNumber numberWithLongLong:status.daemonStartTime],
        @"lastStateTransitionTime":
            [NSNumber numberWithLongLong:status.lastStateTransitionTime],
        @"errorDetail": errorDetail,
        @"activeProfileIndex":
            [NSNumber numberWithUnsignedInt:status.activeProfileIndex],
    };
    [snapshot setObject:statusDictionary forKey:@"status"];

    NSError *error = nil;
    BOOL written = SGAtomicWritePropertyList(snapshot,
        SGPath(SG_PUBLIC_STATE_PATH), 0644, &error);
    if (!written) {
        SGLOGE(SGDaemon, "code=%s reason=%s",
               SGND_PUBLIC_STATE_WRITE_FAILED,
               [[error description] UTF8String]);
    }
    return written;
}

- (void)schedulePublicStateSnapshot {
    dispatch_async(_storageQueue, ^{
        @autoreleasepool {
            [self _writePublicStateSnapshot];
        }
    });
}

- (BOOL)_applyDurableEvent:(NSDictionary *)event {
    if ([[event objectForKey:SGDurableEventFormatVersionKey] integerValue] != 1) {
        return NO;
    }
    NSString *type = [event objectForKey:SGDurableEventTypeKey];
    NSString *bundleID = [event objectForKey:SGDurableEventBundleIdentifierKey];
    if (![type isKindOfClass:[NSString class]] ||
        !SG_IsIdentifierStringSafe(bundleID)) {
        return NO;
    }

    if ([type isEqualToString:SGDurableEventSetAppEnabled]) {
        NSNumber *enabled = [event objectForKey:SGDurableEventEnabledKey];
        if (![enabled isKindOfClass:[NSNumber class]]) return NO;
        return [self performSetAppEnabled:[enabled boolValue]
                      forBundleIdentifier:bundleID];
    }
    if ([type isEqualToString:SGDurableEventClearAppIntent]) {
        return [self performClearAppIntentForBundleIdentifier:bundleID];
    }
    if ([type isEqualToString:SGDurableEventDeleteApp]) {
        return [self performDeleteAppStateForBundleIdentifier:bundleID];
    }
    return NO;
}

- (void)drainDurableEventInbox {
    dispatch_async(_storageQueue, ^{
        @autoreleasepool {
            NSArray *events = SGDurableEventPendingEvents(
                SGPath(SG_DURABLE_EVENT_INBOX_PATH));
            NSMutableSet *blockedBundles = [NSMutableSet set];
            for (NSDictionary *event in events) {
                NSString *type = [event objectForKey:SGDurableEventTypeKey];
                NSString *bundleID =
                    [event objectForKey:SGDurableEventBundleIdentifierKey];
                BOOL knownType =
                    [type isEqualToString:SGDurableEventSetAppEnabled] ||
                    [type isEqualToString:SGDurableEventClearAppIntent] ||
                    [type isEqualToString:SGDurableEventDeleteApp];
                BOOL payloadValid =
                    ![type isEqualToString:SGDurableEventSetAppEnabled] ||
                    [[event objectForKey:SGDurableEventEnabledKey]
                        isKindOfClass:[NSNumber class]];
                BOOL structurallyValid =
                    [[event objectForKey:SGDurableEventFormatVersionKey]
                        integerValue] == 1 &&
                    [type isKindOfClass:[NSString class]] &&
                    SG_IsIdentifierStringSafe(bundleID) &&
                    knownType && payloadValid;
                if (!structurallyValid) {
                    SGLOGE(SGDaemon, "code=%s file=%s action=quarantine",
                           SGND_DURABLE_EVENT_INVALID,
                           [[[event objectForKey:SGDurableEventFilePathKey]
                               lastPathComponent] UTF8String]);
                    SGDurableEventQuarantine(event);
                    continue;
                }

                /* Preserve ordering for repeated choices concerning one app,
                 * without allowing a temporarily uncommittable registration
                 * to block an unrelated app's uninstall cleanup. */
                if ([blockedBundles containsObject:bundleID]) continue;

                if ([self _applyDurableEvent:event]) {
                    SGDurableEventRemove(event);
                    SGLOGI(SGDaemon, "code=%s type=%s bundle=%s",
                           SGND_DURABLE_EVENT_APPLIED, [type UTF8String],
                           [bundleID UTF8String]);
                } else {
                    SGLOGW(SGDaemon, "code=%s type=%s bundle=%s action=retry_later",
                           SGND_DURABLE_EVENT_DEFERRED, [type UTF8String],
                           [bundleID UTF8String]);
                    [blockedBundles addObject:bundleID];
                }
            }
        }
    });
}

- (void)performProfileWipeInline {
    @autoreleasepool {
        NSInteger profileIdx = [[SGConfiguration sharedConfiguration] activeProfileIndex];
        NSString *profilePath = SGPath([NSString stringWithFormat:
            SG_PROFILE_PLIST_FORMAT, (long)profileIdx]);
        NSMutableDictionary *profile = [NSMutableDictionary dictionaryWithContentsOfFile:profilePath] ?: [NSMutableDictionary dictionary];

        SGKeychain_DeletePrivateKey(profileIdx);

        [profile removeObjectForKey:@"device_address"];
        [profile removeObjectForKey:@"privateKey"];
        SGPersistSharedPlist(profile, profilePath);
        [[SGConfiguration sharedConfiguration] reloadFromDisk];
    }
}

- (BOOL)performSaveProfileAtIndex:(NSInteger)profileIdx
                    serverAddress:(NSString *)serverAddress
                    certificatePEM:(NSString *)certificatePEM {
    if (profileIdx < 1 || profileIdx > 5) return NO;

    NSString *address = [serverAddress stringByTrimmingCharactersInSet:
                         [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (!SG_IsIdentifierStringSafe(address) ||
        [address lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > SGP_SERVER_ADDRESS_MAX_BYTES) {
        return NO;
    }

    BOOL hasNewCertificate = ([certificatePEM length] > 0);
    if (hasNewCertificate && !SGCertificatePEMLooksValid(certificatePEM)) return NO;

    BOOL isActive = ([[SGConfiguration sharedConfiguration] activeProfileIndex] == profileIdx);
    NSString *profilePath = SGPath([NSString stringWithFormat:
        SG_PROFILE_PLIST_FORMAT, (long)profileIdx]);
    NSMutableDictionary *profile =
        [NSMutableDictionary dictionaryWithContentsOfFile:profilePath]
        ?: [NSMutableDictionary dictionary];

    NSString *oldAddress = [profile objectForKey:@"server_address"];
    NSString *oldCertPath = [profile objectForKey:@"server_pub_key"];
    NSString *storedCertPath = SGProfileCertificatePathForIndex(profileIdx);
    NSString *certDiskPath = SGPath(storedCertPath);

    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *certDir = SGPath(kSGProfileCertificateDirectory);
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:certDir isDirectory:&isDir]) {
        if (![fm createDirectoryAtPath:certDir withIntermediateDirectories:YES attributes:nil error:nil]) {
            return NO;
        }
    } else if (!isDir) {
        return NO;
    }

    BOOL certificateChanged = hasNewCertificate;
    if (hasNewCertificate) {
        if (![certificatePEM writeToFile:certDiskPath
                              atomically:YES
                                encoding:NSUTF8StringEncoding
                                   error:nil]) {
            return NO;
        }
        chmod([certDiskPath fileSystemRepresentation], 0644);
    } else if ([oldCertPath length] > 0) {
        if (![oldCertPath isEqualToString:storedCertPath]) {
            NSString *oldDiskPath = SGPath(oldCertPath);
            if (![fm fileExistsAtPath:oldDiskPath]) {
                return NO;
            }
            [fm removeItemAtPath:certDiskPath error:nil];
            if (![fm copyItemAtPath:oldDiskPath toPath:certDiskPath error:nil]) {
                return NO;
            }
        } else if (![fm fileExistsAtPath:certDiskPath]) {
            return NO;
        }
    } else {
        return NO;
    }

    BOOL addressChanged = (oldAddress && ![oldAddress isEqualToString:address]);

    [profile setObject:address forKey:@"server_address"];
    [profile setObject:storedCertPath forKey:@"server_pub_key"];

    if (addressChanged || certificateChanged) {
        SGKeychain_DeletePrivateKey(profileIdx);
        [profile removeObjectForKey:@"device_address"];
        [profile removeObjectForKey:@"privateKey"];
    }

    if (!SGPersistSharedPlist(profile, profilePath)) {
        return NO;
    }

    [[SGConfiguration sharedConfiguration] reloadFromDisk];

    if (isActive) {
        if (addressChanged || certificateChanged) {
            [[SGDatabaseManager sharedManager] clearAllTokens];
            [[SGDatabaseManager sharedManager] clearAllDNSCache];
        }
        [self handleEvent:SGEventConfigReloaded payload:nil];
    }

    [self drainDurableEventInbox];
    [self schedulePublicStateSnapshot];
    return YES;
}

- (BOOL)performDeleteProfileAtIndex:(NSInteger)profileIdx {
    if (profileIdx < 1 || profileIdx > 5) return NO;

    BOOL wasActive = ([[SGConfiguration sharedConfiguration] activeProfileIndex] == profileIdx);
    NSString *profilePath = SGPath([NSString stringWithFormat:
        SG_PROFILE_PLIST_FORMAT, (long)profileIdx]);
    NSString *certPath = SGPath(SGProfileCertificatePathForIndex(profileIdx));
    NSFileManager *fm = [NSFileManager defaultManager];

    /* Delete the keychain entry first.  If the plist write fails afterward
     * we'd have a no-key + no-plist state, which is fine — the slot is
     * just gone.  The reverse order would risk a no-key + intact-plist
     * state where the daemon thinks the slot is registered but can't auth. */
    SGKeychain_DeletePrivateKey(profileIdx);
    if ([fm fileExistsAtPath:certPath]) {
        [fm removeItemAtPath:certPath error:nil];
    }

    if ([fm fileExistsAtPath:profilePath]) {
        NSError *err = nil;
        if (![fm removeItemAtPath:profilePath error:&err]) {
            SGLOGE(SGDaemon, "profile-delete: plist removal failed idx=%ld errno=%d",
                   (long)profileIdx, (int)[err code]);
            return NO;
        }
    }

    if (![[SGDatabaseManager sharedManager] clearOperationalStateForProfile:profileIdx]) {
        SGLOGE(SGDaemon, "profile-delete: database cleanup failed idx=%ld",
               (long)profileIdx);
        return NO;
    }

    [[SGConfiguration sharedConfiguration] reloadFromDisk];

    if (wasActive) {
        /* Bump the FSM to act on the now-missing profile.  ConfigReloaded
         * is the existing reload-driven event; the FSM handler maps it to
         * Disabled when the user-intent is unchanged but the profile is
         * gone (no valid config). */
        [self handleEvent:SGEventConfigReloaded payload:nil];
    }

    [self schedulePublicStateSnapshot];
    return YES;
}

- (BOOL)performSetActiveProfileAtIndex:(NSInteger)profileIdx {
    if (profileIdx < 1 || profileIdx > 5) return NO;

    NSString *profilePath = SGPath([NSString stringWithFormat:
        SG_PROFILE_PLIST_FORMAT, (long)profileIdx]);
    if (![[NSFileManager defaultManager] fileExistsAtPath:profilePath]) return NO;

    if ([[SGConfiguration sharedConfiguration] activeProfileIndex] == profileIdx) return YES;

    BOOL persisted = [self _updateMainPreferences:^(NSMutableDictionary *preferences) {
        [preferences setObject:[NSNumber numberWithInteger:profileIdx]
                        forKey:@"activeProfile"];
    }];
    if (!persisted) return NO;

    [[SGConfiguration sharedConfiguration] reloadFromDisk];

    @synchronized(_seenMessageIDs) {
        [_seenMessageIDs removeAllObjects];
    }
    [self reconcileTokensWithPlist];
    [self handleEvent:SGEventConfigReloaded payload:nil];
    [self _kickLocalDeliveryDrain];
    [self drainDurableEventInbox];
    [self schedulePublicStateSnapshot];

    return YES;
}

#pragma mark - SpringBoard Push Delivery (via SGControlChannel)

- (kern_return_t)_deliverPushTopic:(NSString *)topic payload:(NSDictionary *)payload {
    if (!_springBoardClient) {
        SGLOGW(SGDaemon, "code=%s bundle=%s result=unavailable", SGND_DELIVERY_SPRINGBOARD_UNAVAILABLE,
                    [topic length] ? [topic UTF8String] : "none");
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
        SGLOGE(SGDaemon, "code=%s bundle=%s bytes=%lu max=%d result=failed", SGND_DELIVERY_PAYLOAD_TOO_LARGE,
                    [topic UTF8String], (unsigned long)[plistData length],
                    SG_CONTROL_MAX_USERINFO_SIZE);
        return KERN_RESOURCE_SHORTAGE;
    }

    SGCPushDeliveryPayload pd;
    memset(&pd, 0, sizeof(pd));
    strlcpy(pd.bundleID, [topic UTF8String], sizeof(pd.bundleID));
    pd.userInfoLength = (uint32_t)[plistData length];
    if (pd.userInfoLength > 0) memcpy(pd.userInfoData, [plistData bytes], pd.userInfoLength);

    NSUInteger sendLen = offsetof(SGCPushDeliveryPayload, userInfoData) + pd.userInfoLength;
    NSData *requestPayload = [NSData dataWithBytes:&pd length:sendLen];

    __block int32_t result = (int32_t)KERN_FAILURE;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    /* The completion may be scheduled after our bounded wait expires.  Give it
     * an independent semaphore ownership reference so a late signal cannot
     * touch the caller's released reference. */
    dispatch_retain(sema);
    [_springBoardClient sendRequest:SGCMSG_PUSH_DELIVERY
                            payload:requestPayload
                            timeout:0
                         completion:^(SGControlError err, const SGControlChannelMessage *response) {
        if (err == SGCERR_OK) {
            OSAtomicCompareAndSwap32Barrier((int32_t)KERN_FAILURE,
                                            (int32_t)KERN_SUCCESS,
                                            &result);
        }
        dispatch_semaphore_signal(sema);
        dispatch_release(sema);
    }];
    /* Bounded wait — channel default is 5s, give it +1s grace for
     * dispatch + completion handler scheduling.  If we time out the
     * semaphore here (channel didn't fire its completion in time, which
     * shouldn't happen but defensive), `result` stays KERN_FAILURE and
     * the caller's local-pending-deliveries retry path will pick the
     * notification up on the next drain. */
    int64_t waitNs = (int64_t)((SG_CONTROL_DEFAULT_REQUEST_TIMEOUT_SEC + 1.0) * NSEC_PER_SEC);
    long waitResult = dispatch_semaphore_wait(
        sema, dispatch_time(DISPATCH_TIME_NOW, waitNs));
    kern_return_t finalResult = (waitResult == 0)
        ? (kern_return_t)OSAtomicAdd32Barrier(0, &result)
        : KERN_FAILURE;
    dispatch_release(sema);

    return finalResult;
}

#pragma mark - Notification Disposition Helpers

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

- (void)_drainLocalPendingDeliveries {
    @autoreleasepool {
        SGDatabaseManager *db = [SGDatabaseManager sharedManager];
        NSArray *pending = [db allLocalPendingDeliveries];
        if ([pending count] == 0) {
            [self _stopLocalDeliveryRetryTimer];
            return;
        }

        [self _startLocalDeliveryRetryTimer];

        int64_t now = (int64_t)time(NULL);
        for (NSDictionary *entry in pending) {
            @autoreleasepool {
                NSData   *msgID      = entry[@"msgID"];
                NSString *bundleID   = entry[@"bundleID"];
                NSData   *serialized = entry[@"payload"];
                int64_t   deviceSeq  = [entry[@"deviceSeq"] longLongValue];
                int64_t   expiresAt  = [entry[@"expiresAt"] longLongValue];
                char msgHex[SGP_MSG_ID_LEN * 2 + 1];
                SGCopyMessageIDHex(msgID, msgHex, sizeof(msgHex));

                if (now > expiresAt) {
                    SGLOGW(SGDaemon, "code=%s msg=%s bundle=%s ack=expired action=remove", SGND_DELIVERY_LOCAL_RETRY_EXPIRED,
                                msgHex, [bundleID UTF8String]);
                    SGP_EnqueueAcknowledgement(msgID, SGP_ACK_EXPIRED);
                    [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
                    [db removeLocalPendingDeliveryForMessageID:msgID];
                    continue;
                }

                NSDictionary *parsed = (NSDictionary *)[NSPropertyListSerialization
                    propertyListFromData:serialized
                        mutabilityOption:NSPropertyListImmutable
                                  format:NULL
                        errorDescription:NULL];
                if (![parsed isKindOfClass:[NSDictionary class]]) {
                    SGLOGE(SGDaemon, "code=%s msg=%s bundle=%s ack=parse_failed action=remove", SGND_DELIVERY_LOCAL_RETRY_BAD_PAYLOAD,
                                msgHex, [bundleID UTF8String]);
                    SGP_EnqueueAcknowledgement(msgID, SGP_ACK_PARSE_FAILED);
                    [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
                    [db removeLocalPendingDeliveryForMessageID:msgID];
                    continue;
                }

                kern_return_t kr = [self _deliverPushTopic:bundleID payload:parsed];
                if (kr == KERN_SUCCESS) {
                    SGLOGI(SGDaemon, "code=%s msg=%s bundle=%s result=delivered", SGND_DELIVERY_LOCAL_RETRY_SUCCEEDED,
                                msgHex, [bundleID UTF8String]);
                    SGP_EnqueueAcknowledgement(msgID, SGP_ACK_SUCCESS);
                    [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
                    [self _advanceLastDeliveredSeqIfNeeded:deviceSeq];
                    [db removeLocalPendingDeliveryForMessageID:msgID];
                }
            }
        }

        if ([[db allLocalPendingDeliveries] count] == 0) {
            [self _stopLocalDeliveryRetryTimer];
        }
    }
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
    if (!SGP_IsConnected()) {
        SGLOGD(SGDaemon, "code=%s reason=not_connected action=ignore", SGND_KEEPALIVE_TIMER_IGNORED);
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

- (void)_probeConnectionLiveness {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        if (!SGP_IsConnected()) return;

        uint32_t assertionID = [[SGAvailability shared]
            createTimedPowerAssertionWithName:@"com.skyglow.sgn.probe"
                                      timeout:(NSTimeInterval)(SGP_PONG_TIMEOUT_SEC + 10)];

        SGP_SendKeepAlivePing();

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                     (int64_t)((SGP_PONG_TIMEOUT_SEC + 5) * NSEC_PER_SEC)),
                       dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            double stillPending = SGP_GetPendingPingAgeWallSeconds();
            if (SGP_IsConnected() && stillPending > (double)SGP_PONG_TIMEOUT_SEC) {
                SGLOGW(SGDaemon, "code=%s pending=%.0fs action=abort_for_reconnect",
                       SGND_KEEPALIVE_PROBE_FAILED, stillPending);
                [self _recordKeepAliveFailureFeedback];
                SGP_AbortConnection();
            }
            [[SGAvailability shared] releasePowerAssertion:assertionID];
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

    [_stateLock lock];
    uint32_t gen = _fsmGeneration;
    [_stateLock unlock];

    /* The ResolvingDNS watchdog is armed centrally from the deadline table in
     * executeTransitionToState; this method only performs the lookup. */
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSDictionary *txt = [SGServerLocator resolveEndpointForServerAddress:address];

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
        SGLOGE(SGDaemon, "code=%s ip=%s port=%s cert=%s result=failed", SGND_CONFIG_BAD_SERVER_FIELDS,
                    ip ? "set" : "missing",
                    portStr ? "set" : "missing",
                    cert ? "set" : "missing");
        strlcpy(_lastErrorDetail, "Missing server IP, port, or certificate", sizeof(_lastErrorDetail));
        [self handleEvent:SGEventConnectFailed payload:nil];
        return;
    }

    [_stateLock lock];
    uint32_t gen = _fsmGeneration;
    [_stateLock unlock];

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
            [certCopy release];

            [self->_stateLock lock];
            isStale = (self->_fsmGeneration != gen);
            [self->_stateLock unlock];

            if (isStale) {
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
                [self handleEvent:SGEventConnectFailed payload:nil];
            }
            [ipCopy release];
        }
    });
}

- (void)startConnectionScopedWorker {
    if (_workerActive) return;
    _workerActive = YES;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        SGLOGI(SGDaemon, "code=%s result=started", SGND_PROTOCOL_WORKER_STARTED);

        BOOL timerDrivenPings = [SGAvailability shared].persistentTimerAvailable;

        while (SGP_IsConnected()) {
            @autoreleasepool {
                double pingInterval = 0.0;
                if (!timerDrivenPings) {
                    [self->_stateLock lock];
                    pingInterval = [self _currentKeepAliveInterval];
                    [self->_stateLock unlock];
                }

                int rc = SGP_ProcessNextIncomingMessage(pingInterval);

                if (rc != SGP_OK) {
                    SGLOGI(SGDaemon, "code=%s rc=%d name=%s result=exited", SGND_PROTOCOL_WORKER_EXITED, rc, SGP_ErrorName(rc));
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
                    break;
                }
            }
        }
        dispatch_async(self->_entryActionQueue, ^{
            [self->_stateLock lock];
            self->_workerActive = NO;
            [self->_stateLock unlock];
        });
        SGLOGI(SGDaemon, "code=%s result=stopped", SGND_PROTOCOL_WORKER_STOPPED);
    });
}

- (void)scheduleTimerForEvent:(SGEvent)event delay:(uint32_t)seconds generation:(uint32_t)generation {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, seconds * NSEC_PER_SEC), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self->_stateLock lock];
        BOOL isStale = (self->_fsmGeneration != generation);
        [self->_stateLock unlock];
        
        if (isStale) {
            SGLOGD(SGDaemon, "code=%s generation=%u event=%ld action=discard", SGND_FSM_TIMER_STALE, generation, (long)event);
            return;
        }
        [self handleEvent:event payload:nil];
    });
}

@end
