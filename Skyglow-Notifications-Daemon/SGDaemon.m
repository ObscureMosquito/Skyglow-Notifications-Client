#import "SGDaemon.h"
#import "SGConfiguration.h"
#import "SGDatabaseManager.h"
#import "SGTokenManager.h"
#import "SGProtocolHandler.h"
#import "SGServerLocator.h"
#import "SGKeepAliveStrategy.h"
#import "SGMachServer.h"
#import "SGPayloadParser.h"
#import "SGCryptoEngine.h"
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <stdatomic.h>
#include <openssl/pem.h>

typedef struct { SGState from; SGState to; } SGTransition;

static const SGTransition kLegalTransitions[] = {
    // Starting
    { SGStateStarting,          SGStateDisabled            },
    { SGStateStarting,          SGStateIdleUnregistered    },
    { SGStateStarting,          SGStateResolvingDNS        },
    { SGStateStarting,          SGStateIdleDNSFailed       },
    { SGStateStarting,          SGStateIdleNoNetwork       },
    { SGStateStarting,          SGStateError               },
    { SGStateStarting,          SGStateErrorBadConfig      },

    // Resolving DNS
    { SGStateResolvingDNS,      SGStateConnecting          },
    { SGStateResolvingDNS,      SGStateIdleDNSFailed       },
    { SGStateResolvingDNS,      SGStateErrorBadConfig      },
    { SGStateResolvingDNS,      SGStateIdleNoNetwork       },
    { SGStateResolvingDNS,      SGStateDisabled            },

    // DNS Failed
    { SGStateIdleDNSFailed,     SGStateResolvingDNS        },
    { SGStateIdleDNSFailed,     SGStateDisabled            },
    { SGStateIdleDNSFailed,     SGStateIdleNoNetwork       },

    // Idle No Network
    { SGStateIdleNoNetwork,     SGStateConnecting          },
    { SGStateIdleNoNetwork,     SGStateDisabled            },
    { SGStateIdleNoNetwork,     SGStateResolvingDNS        },

    // Unregistered
    { SGStateIdleUnregistered,  SGStateResolvingDNS        },
    { SGStateIdleUnregistered,  SGStateDisabled            },

    // Connecting
    { SGStateConnecting,        SGStateAuthenticating      },
    { SGStateConnecting,        SGStateRegistering         }, 
    { SGStateConnecting,        SGStateBackingOff          },
    { SGStateConnecting,        SGStateIdleNoNetwork       },
    { SGStateConnecting,        SGStateIdleCircuitOpen     },
    { SGStateConnecting,        SGStateErrorBadConfig      },

    // Registering
    { SGStateRegistering,       SGStateAuthenticating      }, 
    { SGStateRegistering,       SGStateBackingOff          }, 
    { SGStateRegistering,       SGStateError               }, 
    { SGStateRegistering,       SGStateIdleNoNetwork       },
    { SGStateRegistering,       SGStateDisabled            },

    // Authenticating
    { SGStateAuthenticating,    SGStateRegistering         }, 
    { SGStateAuthenticating,    SGStateConnected           },
    { SGStateAuthenticating,    SGStateBackingOff          },
    { SGStateAuthenticating,    SGStateErrorAuth           },
    { SGStateAuthenticating,    SGStateDisabled            }, 
    { SGStateAuthenticating,    SGStateIdleNoNetwork       },
    { SGStateAuthenticating,    SGStateIdleUnregistered    },
    { SGStateAuthenticating,    SGStateErrorBadConfig      },

    // Connected
    { SGStateConnected,         SGStateConnecting          }, 
    { SGStateConnected,         SGStateBackingOff          },
    { SGStateConnected,         SGStateIdleNoNetwork       },
    { SGStateConnected,         SGStateDisabled            },
    { SGStateConnected,         SGStateResolvingDNS        },

    // Backing Off
    { SGStateBackingOff,        SGStateConnecting          },
    { SGStateBackingOff,        SGStateResolvingDNS        },
    { SGStateBackingOff,        SGStateIdleNoNetwork       },
    { SGStateBackingOff,        SGStateIdleCircuitOpen     },
    { SGStateBackingOff,        SGStateDisabled            },

    // Circuit Open
    { SGStateIdleCircuitOpen,   SGStateConnecting          },
    { SGStateIdleCircuitOpen,   SGStateIdleNoNetwork       },
    { SGStateIdleCircuitOpen,   SGStateDisabled            },
    { SGStateIdleCircuitOpen,   SGStateResolvingDNS        },

    // Error Auth
    { SGStateErrorAuth,         SGStateDisabled            },
    { SGStateErrorAuth,         SGStateResolvingDNS        },

    // Error Bad Config
    { SGStateErrorBadConfig,    SGStateDisabled            },
    { SGStateErrorBadConfig,    SGStateResolvingDNS        },

    // Generic Error
    { SGStateError,             SGStateDisabled            },
    { SGStateError,             SGStateResolvingDNS        },

    // Disabled
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
    SGKeepAliveAlgorithm   _keepAliveAlgo;
    NSMutableOrderedSet   *_seenMessageIDs;
    
    // FSM generation counter: incremented on every state transition.
    // Used only for timer cancellation (stale timers become no-ops).
    uint32_t               _fsmGeneration;
    
    // Connection-scoped worker guard: prevents duplicate workers.
    BOOL                   _workerActive;
    
    // Dedicated serial queue for state entry actions to prevent races.
    dispatch_queue_t       _entryActionQueue;
}

- (id)init {
    if ((self = [super init])) {
        _stateLock           = [[NSLock alloc] init];
        _consecutiveFailures = 0;
        _fsmGeneration       = 0;
        _seenMessageIDs      = [[NSMutableOrderedSet alloc] initWithCapacity:200];
        _entryActionQueue    = dispatch_queue_create("com.skyglow.daemon.entry", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)dealloc {
    [_stateLock release];
    [_seenMessageIDs release];
    dispatch_release(_entryActionQueue);
    [super dealloc];
}

- (void)start {
    // Purge orphaned tokens and generate missing ones before connecting
    [self reconcileTokensWithPlist];
    
    [_stateLock lock];
    double savedInterval = [[SGDatabaseManager sharedManager] loadKeepAliveIntervalForWiFi:YES];
    SGKeepAlive_Initialize(&_keepAliveAlgo, true, savedInterval);
    [_stateLock unlock];
    
    [self handleEvent:SGEventStartRequested payload:nil];
}

/// Compares the appStatus plist (source of truth for which apps use Skyglow)
/// against the token database. Removes orphaned DB entries and flags missing tokens
/// for generation on next connect.
- (void)reconcileTokensWithPlist {
    NSString *plistPath = SGPath(@"/var/mobile/Library/Preferences/com.skyglow.sndp.plist");
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    NSDictionary *appStatus = [prefs objectForKey:@"appStatus"] ?: @{};
    
    // Collect enabled bundle IDs from the plist
    NSMutableSet *plistBundles = [NSMutableSet set];
    for (NSString *bundleID in appStatus) {
        if ([[appStatus objectForKey:bundleID] boolValue]) {
            [plistBundles addObject:bundleID];
        }
    }
    
    SGDatabaseManager *db = [SGDatabaseManager sharedManager];
    NSSet *dbBundles = [db registeredBundleIdentifiers];
    
    // 1. Remove orphaned tokens (in DB but not in plist)
    for (NSString *bundleID in dbBundles) {
        if (![plistBundles containsObject:bundleID]) {
            [db removeTokenForBundleIdentifier:bundleID];
            NSLog(@"[SGDaemon] Removed orphaned token for: %@", bundleID);
        }
    }
    
    // 2. Generate tokens for apps in plist but missing from DB
    //    Only if the device is registered (has a server address) — otherwise
    //    token generation will fail because there's no server to derive keys from.
    NSString *serverAddr = [[SGConfiguration sharedConfiguration] serverAddress];
    if (serverAddr && [serverAddr length] > 0) {
        SGTokenManager *tokenMgr = [[SGTokenManager alloc] init];
        for (NSString *bundleID in plistBundles) {
            if (![dbBundles containsObject:bundleID]) {
                NSError *err = nil;
                NSData *token = [tokenMgr synchronizedTokenForBundleIdentifier:bundleID error:&err];
                if (token) {
                    NSLog(@"[SGDaemon] Generated missing token for: %@", bundleID);
                } else {
                    NSLog(@"[SGDaemon] Failed to generate token for %@: %@", bundleID, err);
                }
            }
        }
        [tokenMgr release];
    } else {
        for (NSString *bundleID in plistBundles) {
            if (![dbBundles containsObject:bundleID]) {
                NSLog(@"[SGDaemon] App %@ needs a token but device is unregistered — will generate after registration", bundleID);
            }
        }
    }
}

// FSM

- (void)handleEvent:(SGEvent)event payload:(id)payload {
    [_stateLock lock];
    
    SGStatusPayload currentStatus;
    SGStatusServer_Current(&currentStatus);
    SGState currentState = (SGState)currentStatus.state;
    
    NSLog(@"[SGDaemon] FSM Rx Event: %ld in State: %s", (long)event, SGState_GetName(currentState));

    // Global Overrides
    if (event == SGEventStopRequested || 
       (event == SGEventConfigReloaded && ![[SGConfiguration sharedConfiguration] isEnabled])) {
        _consecutiveFailures = 0; // Explicitly reset error count on disable
        [self executeTransitionToState:SGStateDisabled backoff:0 ip:NULL];
        [_stateLock unlock];
        return;
    }

    if (event == SGEventNetworkDown) {
        if (currentState != SGStateDisabled && currentState != SGStateErrorBadConfig) {
            [self executeTransitionToState:SGStateIdleNoNetwork backoff:0 ip:NULL];
        }
        [_stateLock unlock];
        return;
    }

    // State-Specific Routing (all transitions go through the FSM — no exceptions)
    switch (currentState) {
        case SGStateStarting:
        case SGStateDisabled:
        case SGStateErrorBadConfig:
        case SGStateIdleUnregistered:
            if (event == SGEventStartRequested || event == SGEventConfigReloaded) {
                _consecutiveFailures = 0; // Start with a fresh retry count
                if ([[SGConfiguration sharedConfiguration] isValid]) {
                    [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
                } else {
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
            if (event == SGEventDNSResolved) {
                NSDictionary *txt = (NSDictionary *)payload;
                [[SGConfiguration sharedConfiguration] setServerIPAddress:txt[@"tcp_addr"]];
                [[SGConfiguration sharedConfiguration] setServerPort:txt[@"tcp_port"]];
                [self executeTransitionToState:SGStateConnecting backoff:0 ip:[txt[@"tcp_addr"] UTF8String]];
            } else if (event == SGEventDNSFailed) {
                [self executeFailureBackoff];
            }
            break;

        case SGStateIdleDNSFailed:
        case SGStateBackingOff:
            if (event == SGEventBackoffTimerFired || event == SGEventNetworkUp) {
                if (event == SGEventNetworkUp) _consecutiveFailures = 0;
                [self executeTransitionToState:SGStateResolvingDNS backoff:0 ip:NULL];
            }
            break;

        case SGStateConnecting:
            if (event == SGEventConnectSuccess) {
                [self executeTransitionToState:SGStateAuthenticating backoff:0 ip:NULL];
            } 
            else if (event == SGEventConnectFailed || event == SGEventDisconnected) {
                [self executeFailureBackoff];
            }
            break;

        case SGStateAuthenticating:
            if (event == SGEventAuthSuccess) {
                _consecutiveFailures = 0;
                [self executeTransitionToState:SGStateConnected backoff:0 ip:NULL];
            } 
            else if (event == SGEventAuthFailed) {
                [self performProfileWipeInline];
                [self executeFailureBackoff];
            }
            else if (event == SGEventDisconnected) {
                [self executeFailureBackoff];
            }
            break;

        case SGStateConnected:
            if (event == SGEventDisconnected) {
                [self executeFailureBackoff];
            }
            break;
            
        case SGStateIdleCircuitOpen:
            if (event == SGEventNetworkUp || event == SGEventConfigReloaded) {
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
        NSLog(@"[SGDaemon] ⚠️ ILLEGAL TRANSITION REJECTED: %s → %s", SGState_GetName((SGState)current.state), SGState_GetName(newState));
        return;
    }

    // Increment generation: invalidates all stale timers and worker threads
    _fsmGeneration++;
    uint32_t capturedGen = _fsmGeneration;

    NSString *currentIPStr = [[SGConfiguration sharedConfiguration] serverIPAddress];
    const char *resolvedIP = ip ? ip : (currentIPStr ? [currentIPStr UTF8String] : NULL);

    SGStatusServer_Post(newState, (uint32_t)_consecutiveFailures, backoff, resolvedIP);
    NSLog(@"[SGDaemon] Transitioned to %s (gen=%u)", SGState_GetName(newState), capturedGen);

    // Execute State Entry Actions on a dedicated serial queue.
    // Capturing `capturedGen` ensures stale entry actions are no-ops.
    dispatch_async(_entryActionQueue, ^{
        // Verify this entry action is still relevant
        [self->_stateLock lock];
        BOOL isStale = (self->_fsmGeneration != capturedGen);
        [self->_stateLock unlock];
        if (isStale) return;

        switch (newState) {
            case SGStateResolvingDNS:
                [self performDNSResolution];
                break;
            case SGStateConnecting:
                [self performSocketConnection];
                break;    
            case SGStateAuthenticating:
                [self startConnectionScopedWorker]; 
                [self scheduleTimerForEvent:SGEventAuthFailed delay:10 generation:capturedGen]; 
                break;
            case SGStateRegistering:
            case SGStateConnected:
                break;
            case SGStateBackingOff:
            case SGStateIdleDNSFailed:
                [self scheduleTimerForEvent:SGEventBackoffTimerFired delay:backoff generation:capturedGen];
                break;
            case SGStateIdleCircuitOpen:
                SGP_AbortConnection();  // Clean up, then wait for NetworkUp
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
    
    // 1. Give up entirely if max failures reached — wait for network change
    if (_consecutiveFailures >= SG_MAX_CONSECUTIVE_FAILURES) {
        NSLog(@"[SGDaemon] Max failures (%d) reached after ~1h. Idling until network change.", SG_MAX_CONSECUTIVE_FAILURES);
        [self executeTransitionToState:SGStateIdleCircuitOpen backoff:0 ip:NULL];
    } 
    else {
        // 2. Exponential growth (2, 4, 8, 16, 32...)
        // (1 << x) is highly efficient bit-shifting math for 2^x
        uint32_t baseDelay = SG_INITIAL_BACKOFF_SECONDS * (1 << (_consecutiveFailures - 1));
        
        // 3. Add Jitter (0 to 5 seconds) to desynchronize mass reconnections
        uint32_t jitter = arc4random_uniform(SG_MAX_JITTER_SECONDS + 1);
        
        // 4. Cap it at the maximum allowed backoff (10 minutes)
        uint32_t finalDelay = baseDelay + jitter;
        if (finalDelay > SG_MAX_BACKOFF_SECONDS) {
            finalDelay = SG_MAX_BACKOFF_SECONDS;
        }

        NSLog(@"[SGDaemon] Backing off for %u seconds (Failure %d/%d)", finalDelay, _consecutiveFailures, SG_MAX_CONSECUTIVE_FAILURES);
        [self executeTransitionToState:SGStateBackingOff backoff:finalDelay ip:NULL];
    }
}

// ── SGProtocolDelegate Implementation ───────────────────────────────

- (void)protocolDidReceiveWelcomeChallenge {
    // Called from the message processing worker thread.
    // Route all state changes through the FSM.
    NSString *clientAddress = [[SGConfiguration sharedConfiguration] deviceAddress];

    if (!clientAddress || [clientAddress length] == 0) {
        // No device address — need first-time registration.
        // Transition Authenticating → Registering is legal in the FSM table.
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
        NSLog(@"[SGDaemon] Profile contains device_address but missing/invalid privateKey! Wiping profile for re-registration.");
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
    
    [self uploadPendingTokensAsync];
}

- (void)protocolDidCompleteTokenRegistration:(NSString *)bundleIdentifier {
    NSLog(@"[SGDaemon] Token registration acknowledged for %@", bundleIdentifier);
}

- (void)uploadPendingTokensAsync {
    NSArray *pending = [[SGDatabaseManager sharedManager] pendingUploadTokens];
    if ([pending count] == 0) return;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        for (NSDictionary *entry in pending) {
            @autoreleasepool {
                NSData   *routingKey = entry[@"routingKey"];
                NSString *bundleID   = entry[@"bundleID"];

                if (!SGP_IsConnected()) break;

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

        NSLog(@"[SGDaemon] Processing Push Notification (MSG_ID: %@)", [msgID description]);

        // ── 1. Deduplication ────────────────────────────────────────
        @synchronized(_seenMessageIDs) {
            if ([_seenMessageIDs containsObject:msgID]) {
                SGP_EnqueueAcknowledgement(msgID, 0);
                return; 
            }
            [_seenMessageIDs addObject:msgID];
            if ([_seenMessageIDs count] > 200) [_seenMessageIDs removeObjectAtIndex:0];
        }

        __block _Atomic IOPMAssertionID assertionID = 0;
        IOPMAssertionID tempID = 0;
        if (IOPMAssertionCreateWithName(kIOPMAssertionTypePreventUserIdleSystemSleep, 
                                        kIOPMAssertionLevelOn, CFSTR("com.skyglow.sgn.processing"), &tempID) == kIOReturnSuccess) {
            atomic_store(&assertionID, tempID);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                IOPMAssertionID expected = tempID;
                if (atomic_compare_exchange_strong(&assertionID, &expected, 0)) IOPMAssertionRelease(expected);
            });
        }

        // ── 3. Processing ───────────────────────────────────────────
        NSData *routingKey = messageDict[@"routing_key"];
        NSDictionary *routingData = [[SGDatabaseManager sharedManager] tokenDataForRoutingKey:routingKey];
        if (!routingData) {
            NSLog(@"[SGDaemon] DROP: Routing Key not found in local Database.");
            goto cleanup_assertion;
        }

        NSData *payloadBytes = messageDict[@"data"];
        if (!payloadBytes) { 
            NSLog(@"[SGDaemon] DROP: Payload data is empty.");
            SGP_EnqueueAcknowledgement(msgID, 2); 
            goto cleanup_assertion; 
        }

        if ([messageDict[@"is_encrypted"] boolValue]) {
            NSLog(@"[SGDaemon] Payload is Encrypted. Attempting AES-256-GCM decryption...");
            NSData *iv = messageDict[@"iv"];
            if (!iv) { 
                NSLog(@"[SGDaemon] DROP: Missing IV for decryption.");
                SGP_EnqueueAcknowledgement(msgID, 1); 
                goto cleanup_assertion; 
            }
            
            payloadBytes = SG_CryptoDecryptAESGCM(payloadBytes, routingData[@"e2eeKey"], iv, nil);
            if (!payloadBytes) { 
                NSLog(@"[SGDaemon] DROP: Decryption failed (Bad Key or MAC Tag Tampering).");
                SGP_EnqueueAcknowledgement(msgID, 1); 
                goto cleanup_assertion; 
            }
        } else {
            NSLog(@"[SGDaemon] Payload is plaintext TLV.");
        }

        NSDictionary *parsed = SG_PayloadParseBinaryData((const uint8_t *)payloadBytes.bytes, (uint32_t)payloadBytes.length);
        if (!parsed || parsed.count == 0) {
            NSLog(@"[SGDaemon] DROP: TLV Parser returned empty dictionary. Malformed binary data?");
            SGP_EnqueueAcknowledgement(msgID, 2);
            goto cleanup_assertion;
        }

        NSLog(@"[SGDaemon] Sending Push to app [%@]: %@", routingData[@"bundleID"], parsed);
        SGMach_SendPushToAppTopic(routingData[@"bundleID"], parsed);
        SGP_EnqueueAcknowledgement(msgID, 0);

cleanup_assertion:
        {
            IOPMAssertionID current = atomic_exchange(&assertionID, 0);
            if (current != 0) IOPMAssertionRelease(current);
        }
    }
}

- (void)protocolDidReceiveKeepAlivePong {
    [_stateLock lock];
    double oldVal = SGKeepAlive_GetCurrentInterval(&_keepAliveAlgo);
    SGKeepAlive_ProcessHeartbeatResult(&_keepAliveAlgo, true);
    double newVal = SGKeepAlive_GetCurrentInterval(&_keepAliveAlgo);
    BOOL isWiFi = _keepAliveAlgo.isWiFi;
    [_stateLock unlock];
    
    if (newVal != oldVal) {
        [[SGDatabaseManager sharedManager] saveKeepAliveInterval:newVal forWiFi:isWiFi];
    }
}

- (void)protocolDidFinishOfflineQueueDrain {
    NSLog(@"[SGDaemon] Server confirmed all offline messages delivered.");
}

- (void)protocolDidReceiveTimeSyncWithOffset:(int64_t)offsetSeconds {
    if (llabs(offsetSeconds) > 60) {
        NSLog(@"[SGDaemon] ⚠️ Significant clock drift detected: %lld seconds", offsetSeconds);
    }
}

// ── Registration flow ───────────────────────────────────────────────

- (void)protocolDidCompleteRegistrationWithAddress:(NSString *)deviceAddress privateKey:(NSString *)privateKeyPEM serverVersion:(uint32_t)serverVersion {
    NSString *profilePath = SGPath(@"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist");
    NSMutableDictionary *profile = [NSMutableDictionary dictionaryWithContentsOfFile:profilePath] ?: [NSMutableDictionary dictionary];

    profile[@"device_address"] = deviceAddress;
    
    NSString *keyPath = @"/var/Library/PreferenceBundles/SGNPreferenceBundle.bundle/com.skyglow.client.pem";
    NSString *absoluteKeyPath = SGPath(keyPath);
    NSString *keyDir = [absoluteKeyPath stringByDeletingLastPathComponent];
    [[NSFileManager defaultManager] createDirectoryAtPath:keyDir withIntermediateDirectories:YES attributes:nil error:nil];
    
    [privateKeyPEM writeToFile:absoluteKeyPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    profile[@"privateKey"] = keyPath;

    if (![profile writeToFile:profilePath atomically:YES]) {
        [self handleEvent:SGEventDisconnected payload:nil];
        return;
    }

    [[SGConfiguration sharedConfiguration] reloadFromDisk];

    [[SGDatabaseManager sharedManager] resetAllTokensToRequireUpload];

    BIO *bio = BIO_new_mem_buf((void *)[privateKeyPEM UTF8String], -1);
    RSA *privKey = bio ? PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL) : NULL;
    if (bio) BIO_free(bio);

    if (!privKey) {
        [self handleEvent:SGEventAuthFailed payload:nil];
        return;
    }

    // Transition Registering → Authenticating through the FSM,
    // so that SGEventAuthSuccess is handled in the correct state.
    [_stateLock lock];
    [self executeTransitionToState:SGStateAuthenticating backoff:0 ip:NULL];
    [_stateLock unlock];
    SGP_BeginLoginHandshake(deviceAddress, privKey);
}

// ── Daemon Control ──────────────────────────────────────────────────

- (void)systemNetworkReachabilityDidChangeWithWWANStatus:(BOOL)isWWAN {
    [_stateLock lock];
    double savedInterval = [[SGDatabaseManager sharedManager] loadKeepAliveIntervalForWiFi:!isWWAN];
    SGKeepAlive_Initialize(&_keepAliveAlgo, !isWWAN, savedInterval); 
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
    // Reconcile tokens before re-connecting — picks up apps registered while disabled
    [self reconcileTokensWithPlist];
    [self handleEvent:SGEventConfigReloaded payload:nil];
}

/// Wipes device registration inline (called while _stateLock is held).
/// Does NOT re-enter handleEvent — avoids NSLock deadlock.
- (void)performProfileWipeInline {
    @autoreleasepool {
        NSString *profilePath = SGPath(@"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist");
        NSMutableDictionary *profile = [NSMutableDictionary dictionaryWithContentsOfFile:profilePath] ?: [NSMutableDictionary dictionary];
        [profile removeObjectForKey:@"device_address"];
        [profile removeObjectForKey:@"privateKey"];
        [profile writeToFile:profilePath atomically:YES];
        [[SGConfiguration sharedConfiguration] reloadFromDisk];
        [[SGDatabaseManager sharedManager] resetAllTokensToRequireUpload];
    }
}

// ── Worker Methods ──────────────────────────────────────────────────

- (void)performDNSResolution {
    NSString *address = [[SGConfiguration sharedConfiguration] serverAddress];
    if (!address) {
        [self handleEvent:SGEventDNSFailed payload:nil];
        return;
    }

    NSDictionary *txt = [SGServerLocator resolveEndpointForServerAddress:address];
    
    if (txt && isValidPort(txt[@"tcp_port"])) {
        [self handleEvent:SGEventDNSResolved payload:txt];
    } else {
        [self handleEvent:SGEventDNSFailed payload:nil];
    }
}

- (void)performSocketConnection {
    NSString *ip = [[SGConfiguration sharedConfiguration] serverIPAddress];
    NSString *portStr = [[SGConfiguration sharedConfiguration] serverPort];
    NSString *cert = [[SGConfiguration sharedConfiguration] serverPubKeyPEM];
    
    if (!ip || !portStr || !cert) {
        NSLog(@"[SGDaemon] Missing IP, Port, or Certificate. Aborting connection.");
        [self handleEvent:SGEventConnectFailed payload:nil];
        return;
    }

    int port = [portStr intValue];
    int rc = SGP_ConnectToServer([ip UTF8String], port, cert);
    
    if (rc == 0) {
        [self handleEvent:SGEventConnectSuccess payload:nil];
    } else {
        [self handleEvent:SGEventConnectFailed payload:nil];
    }
}

/// Connection-scoped worker: starts once when the socket connects and
/// runs until the socket disconnects or returns an error. Does NOT check
/// the FSM generation — the generation counter is only for timers.
/// This is the APNS-style reader: one reader per connection lifetime.
- (void)startConnectionScopedWorker {
    // Guard: only one worker per connection. The Registering → Authenticating
    // re-entry calls this again, but the flag prevents a duplicate.
    if (_workerActive) return;
    _workerActive = YES;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSLog(@"[SGDaemon] Connection worker started.");
        while (SGP_IsConnected()) {
            [self->_stateLock lock];
            double pingInterval = SGKeepAlive_GetCurrentInterval(&self->_keepAliveAlgo);
            [self->_stateLock unlock];
            
            int rc = SGP_ProcessNextIncomingMessage(pingInterval);
            
            if (rc != SGP_OK) {
                NSLog(@"[SGDaemon] Connection worker exited with code: %d", rc);
                if (rc == SGP_ERR_AUTH) {
                    [self handleEvent:SGEventAuthFailed payload:nil];
                } else {
                    [self handleEvent:SGEventDisconnected payload:nil];
                }
                break;
            }
        }
        self->_workerActive = NO;
        NSLog(@"[SGDaemon] Connection worker stopped.");
    });
}

- (void)scheduleTimerForEvent:(SGEvent)event delay:(uint32_t)seconds generation:(uint32_t)generation {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, seconds * NSEC_PER_SEC), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self->_stateLock lock];
        BOOL isStale = (self->_fsmGeneration != generation);
        [self->_stateLock unlock];
        
        if (isStale) {
            NSLog(@"[SGDaemon] Timer (gen=%u) for event %ld expired but generation changed, discarding.", generation, (long)event);
            return;
        }
        [self handleEvent:event payload:nil];
    });
}

@end