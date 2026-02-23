#import "SGDaemon.h"
#import "SGConfiguration.h"
#import "SGDatabaseManager.h"
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
    { SGStateStarting,          SGStateDisabled            },
    { SGStateStarting,          SGStateIdleUnregistered    },
    { SGStateStarting,          SGStateResolvingDNS        },
    { SGStateStarting,          SGStateIdleDNSFailed       },
    { SGStateStarting,          SGStateIdleNoNetwork       },
    { SGStateStarting,          SGStateError               },
    { SGStateStarting,          SGStateErrorBadConfig      },
    { SGStateResolvingDNS,      SGStateConnecting          },
    { SGStateResolvingDNS,      SGStateIdleDNSFailed       },
    { SGStateResolvingDNS,      SGStateErrorBadConfig      },
    { SGStateIdleDNSFailed,     SGStateResolvingDNS        },
    { SGStateIdleDNSFailed,     SGStateDisabled            },
    { SGStateIdleNoNetwork,     SGStateConnecting          },
    { SGStateIdleNoNetwork,     SGStateDisabled            },
    { SGStateIdleNoNetwork,     SGStateResolvingDNS        },
    { SGStateIdleUnregistered,  SGStateResolvingDNS        },
    { SGStateIdleUnregistered,  SGStateDisabled            },
    { SGStateConnecting,        SGStateAuthenticating      },
    { SGStateConnecting,        SGStateRegistering         }, 
    { SGStateConnecting,        SGStateBackingOff          },
    { SGStateConnecting,        SGStateIdleNoNetwork       },
    { SGStateConnecting,        SGStateIdleCircuitOpen     },
    { SGStateConnecting,        SGStateErrorBadConfig      },
    { SGStateRegistering,       SGStateAuthenticating      }, 
    { SGStateRegistering,       SGStateBackingOff          }, 
    { SGStateRegistering,       SGStateError               }, 
    { SGStateAuthenticating,    SGStateRegistering         }, 
    { SGStateAuthenticating,    SGStateConnected           },
    { SGStateAuthenticating,    SGStateBackingOff          },
    { SGStateAuthenticating,    SGStateErrorAuth           },
    { SGStateAuthenticating,    SGStateDisabled            }, 
    { SGStateConnected,         SGStateConnecting          }, 
    { SGStateConnected,         SGStateBackingOff          },
    { SGStateConnected,         SGStateIdleNoNetwork       },
    { SGStateConnected,         SGStateDisabled            },
    { SGStateConnected,         SGStateResolvingDNS        },
    { SGStateBackingOff,        SGStateConnecting          },
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
    { SGStateDisabled,          SGStateResolvingDNS        },
    { SGStateDisabled,          SGStateIdleUnregistered    },
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
    BOOL                   _isRunning;
    BOOL                   _shouldDisconnect;
    int                    _consecutiveFailures;
    dispatch_semaphore_t   _loopExitSema;
    dispatch_semaphore_t   _wakeupSema;
    SGKeepAliveAlgorithm   _keepAliveAlgo;
    NSMutableOrderedSet   *_seenMessageIDs; 
}

- (id)init {
    if ((self = [super init])) {
        _stateLock           = [[NSLock alloc] init];
        _isRunning           = NO;
        _shouldDisconnect    = NO;
        _consecutiveFailures = 0;
        _loopExitSema        = dispatch_semaphore_create(0);
        _wakeupSema          = dispatch_semaphore_create(0);
        _seenMessageIDs      = [[NSMutableOrderedSet alloc] initWithCapacity:200];
    }
    return self;
}

- (void)dealloc {
    [_stateLock release];
    [_seenMessageIDs release];
    dispatch_release(_loopExitSema);
    dispatch_release(_wakeupSema);
    [super dealloc];
}

// ── FSM Core ────────────────────────────────────────────────────────

- (void)transitionToState:(SGState)newState {
    [self transitionToState:newState backoffSeconds:0 serverIP:NULL];
}

- (void)transitionToState:(SGState)newState backoffSeconds:(uint32_t)backoff serverIP:(const char *)serverIP {
    SGStatusPayload current;
    SGStatusServer_Current(&current); // Corrected
    SGState currentState = (SGState)current.state;

    if (!isLegalTransition(currentState, newState)) {
        NSLog(@"[SGDaemon] ⚠️ ILLEGAL TRANSITION: %s → %s", SGState_GetName(currentState), SGState_GetName(newState));
    }

    [_stateLock lock];
    int failures = _consecutiveFailures;
    [_stateLock unlock];

    const char *ip = serverIP;
    NSString *currentIPStr = [[SGConfiguration sharedConfiguration] serverIPAddress];
    if (!ip && currentIPStr) ip = [currentIPStr UTF8String];

    NSLog(@"[SGDaemon] %s → %s (failures=%d, backoff=%us)", SGState_GetName(currentState), SGState_GetName(newState), failures, backoff);
    
    SGStatusServer_Post(newState, (uint32_t)failures, backoff, ip); // Corrected
}

// ── SGProtocolDelegate Implementation ───────────────────────────────

- (void)protocolDidReceiveWelcomeChallenge {
    NSString *clientAddress = [self getClientAddress];

    if (!clientAddress || [clientAddress length] == 0) {
        [self transitionToState:SGStateRegistering];
        NSString *proposed = SGP_BeginFirstTimeRegistration();
        if (!proposed) [self transitionToState:SGStateBackingOff];
        return;
    }

    RSA *privKey = SG_CryptoGetClientPrivateKey();
    if (!privKey) {
        [self transitionToState:SGStateErrorBadConfig];
        [_stateLock lock]; _shouldDisconnect = YES; [_stateLock unlock];
        return;
    }

    SGP_BeginLoginHandshake(clientAddress, privKey);
}

- (void)protocolDidAuthenticateSuccessfully {
    [_stateLock lock];
    _consecutiveFailures = 0;
    [_stateLock unlock];

    [self transitionToState:SGStateConnected];

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
                NSLog(@"[SGDaemon] Duplicate received, silently acknowledging");
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

// ── Registration flow ───────────────────────────────────────────────

- (void)protocolDidCompleteRegistrationWithAddress:(NSString *)deviceAddress privateKey:(NSString *)privateKeyPEM serverVersion:(uint32_t)serverVersion {
    NSString *profilePath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
    NSMutableDictionary *profile = [NSMutableDictionary dictionaryWithContentsOfFile:profilePath] ?: [NSMutableDictionary dictionary];

    profile[@"device_address"] = deviceAddress;
    profile[@"privateKey"]     = privateKeyPEM;

    if (![profile writeToFile:profilePath atomically:YES]) {
        [self transitionToState:SGStateError];
        [_stateLock lock]; _shouldDisconnect = YES; [_stateLock unlock];
        return;
    }

    [[SGDatabaseManager sharedManager] resetAllTokensToRequireUpload];

    BIO *bio = BIO_new_mem_buf((void *)[privateKeyPEM UTF8String], -1);
    RSA *privKey = bio ? PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL) : NULL;
    if (bio) BIO_free(bio);

    if (!privKey) {
        [self transitionToState:SGStateError];
        [_stateLock lock]; _shouldDisconnect = YES; [_stateLock unlock];
        return;
    }

    [self transitionToState:SGStateAuthenticating];
    SGP_BeginLoginHandshake(deviceAddress, privKey);
}

// ── Daemon Control ──────────────────────────────────────────────────

- (void)handleConfigurationReloadRequest {
    @autoreleasepool {
        NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
        NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];

        if (!prefs || ![[prefs objectForKey:@"enabled"] boolValue]) {
            [self requestGracefulDisconnect];
            [self transitionToState:SGStateDisabled];
            return;
        }

        NSString *profilePath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
        NSDictionary *profile = [NSDictionary dictionaryWithContentsOfFile:profilePath];
        NSString *newServerAddr = profile[@"server_address"];

        if (![newServerAddr isKindOfClass:[NSString class]] || [newServerAddr length] == 0) {
            [self requestGracefulDisconnect];
            [self transitionToState:SGStateIdleUnregistered];
            return;
        }

        [_stateLock lock];
        BOOL isRunningNow = _isRunning;
        [_stateLock unlock];

        if ([newServerAddr isEqualToString:[[SGConfiguration sharedConfiguration] serverAddress]]) {
            if (isRunningNow) return; 

            // Address didn't change, but we are currently disabled/stopped. Needs restart!
            [_stateLock lock];
            _shouldDisconnect = NO;
            [_stateLock unlock];

            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                [self runPrimaryConnectionLoop];
            });
            return;
        }

        [self requestGracefulDisconnect];
        if (isRunningNow) {
            dispatch_semaphore_wait(_loopExitSema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
        }

        [[SGConfiguration sharedConfiguration] setServerAddress:newServerAddr];
        [self transitionToState:SGStateResolvingDNS];

        NSDictionary *txt = nil;
        for (int attempt = 1; attempt <= 3; attempt++) {
            txt = [SGServerLocator resolveEndpointForServerAddress:newServerAddr];
            if (txt) break;
            if (attempt < 3) sleep(10);
        }

        if (!txt) {
            [self transitionToState:SGStateIdleDNSFailed];
            return;
        }

        [[SGConfiguration sharedConfiguration] setServerIPAddress:txt[@"tcp_addr"]];
        [[SGConfiguration sharedConfiguration] setServerPort:txt[@"tcp_port"]];

        // We successfully resolved the new address. Kickstart the loop again.
        [_stateLock lock];
        _shouldDisconnect = NO;
        [_stateLock unlock];

        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [self runPrimaryConnectionLoop];
        });
    }
}

- (void)systemNetworkReachabilityDidChangeWithWWANStatus:(BOOL)isWWAN {
    [_stateLock lock];
    BOOL alreadyRunning = _isRunning;
    if (!alreadyRunning) {
        _isRunning = YES;
        _shouldDisconnect = NO;
    }
    
    _consecutiveFailures = 0;
    double savedInterval = [[SGDatabaseManager sharedManager] loadKeepAliveIntervalForWiFi:!isWWAN];
    SGKeepAlive_Initialize(&_keepAliveAlgo, !isWWAN, savedInterval); 
    [_stateLock unlock];

    dispatch_semaphore_signal(_wakeupSema);

    if (!alreadyRunning) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [self runPrimaryConnectionLoop];
        });
    }
}

- (void)requestGracefulDisconnect {
    [_stateLock lock];
    _shouldDisconnect = YES;
    [_stateLock unlock];
    SGP_SendClientDisconnect();
    SGP_AbortConnection();
    dispatch_semaphore_signal(_wakeupSema);
}

- (void)runPrimaryConnectionLoop {
    [_stateLock lock];
    if (_isRunning) { [_stateLock unlock]; return; }
    _isRunning = YES;
    [_stateLock unlock];

    // Clear any pending wakeups from previous runs
    while (dispatch_semaphore_wait(_wakeupSema, DISPATCH_TIME_NOW) == 0) {}

    NSString *pubKey = [self getServerPubKey];
    if (!pubKey || [pubKey length] == 0) {
        [self transitionToState:SGStateErrorBadConfig];
        goto loop_exit;
    }

    while (1) {
        @autoreleasepool {
            [_stateLock lock];
            BOOL stop = _shouldDisconnect;
            int failures = _consecutiveFailures;
            [_stateLock unlock];
            
            if (stop) break;

            NSString *currentIPStr = [[SGConfiguration sharedConfiguration] serverIPAddress];
            NSString *currentPortStr = [[SGConfiguration sharedConfiguration] serverPort];

            // ─── 1. Self-Healing DNS Resolution ─────────────────────────────
            if (!currentIPStr || !isValidPort(currentPortStr)) {
                NSString *serverAddr = [[SGConfiguration sharedConfiguration] serverAddress];
                if (!serverAddr || [serverAddr length] == 0) {
                    [self transitionToState:SGStateErrorBadConfig];
                    break;
                }
                
                [self transitionToState:SGStateResolvingDNS];
                NSDictionary *txt = [SGServerLocator resolveEndpointForServerAddress:serverAddr];
                
                if (!txt || !txt[@"tcp_addr"] || !txt[@"tcp_port"]) {
                    [self transitionToState:SGStateIdleDNSFailed];
                    // Wait 5 seconds before trying to resolve DNS again
                    dispatch_semaphore_wait(_wakeupSema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
                    continue; 
                }
                
                // Cache the newly resolved endpoint in the Singleton
                [[SGConfiguration sharedConfiguration] setServerIPAddress:txt[@"tcp_addr"]];
                [[SGConfiguration sharedConfiguration] setServerPort:txt[@"tcp_port"]];
                currentIPStr = txt[@"tcp_addr"];
                currentPortStr = txt[@"tcp_port"];
            }
            // ────────────────────────────────────────────────────────────────

            int serverPort = [currentPortStr intValue];
            const char *ipCStr = [currentIPStr UTF8String];

            if (failures >= SG_MAX_CONSECUTIVE_FAILURES) {
                [self transitionToState:SGStateIdleCircuitOpen backoffSeconds:SG_CIRCUIT_OPEN_WAIT_SECONDS serverIP:ipCStr];
                dispatch_semaphore_wait(_wakeupSema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)SG_CIRCUIT_OPEN_WAIT_SECONDS * NSEC_PER_SEC));
                [_stateLock lock]; _consecutiveFailures = 0; [_stateLock unlock];
                continue;
            }

            // Exponential backoff with jitter
            int backoff = SG_INITIAL_BACKOFF_SECONDS;
            for (int i = 0; i < failures && backoff < SG_MAX_BACKOFF_SECONDS; i++) backoff = MIN(backoff * 2, SG_MAX_BACKOFF_SECONDS);
            int jitter = (int)(arc4random_uniform(SG_MAX_JITTER_SECONDS + 1));

            [self transitionToState:SGStateConnecting backoffSeconds:0 serverIP:ipCStr];

            if (SGKeepAlive_GetCurrentInterval(&_keepAliveAlgo) == 0.0) {
                double savedInterval = [[SGDatabaseManager sharedManager] loadKeepAliveIntervalForWiFi:YES];
                SGKeepAlive_Initialize(&_keepAliveAlgo, YES, savedInterval); 
            }

            SGP_SetDelegate(self);
            int cr = SGP_ConnectToServer(ipCStr, serverPort, pubKey);

            if (cr != 0) {
                [_stateLock lock]; failures = ++_consecutiveFailures; [_stateLock unlock];
                int delay = MIN(backoff + jitter, SG_MAX_BACKOFF_SECONDS);
                [self transitionToState:SGStateBackingOff backoffSeconds:(uint32_t)delay serverIP:ipCStr];
                dispatch_semaphore_wait(_wakeupSema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)delay * NSEC_PER_SEC));
                continue;
            }

            [self transitionToState:SGStateAuthenticating];
            BOOL wasReplaced = NO;

            while (1) {
                @autoreleasepool {
                    [_stateLock lock]; BOOL stopInner = _shouldDisconnect; [_stateLock unlock];
                    if (stopInner) break;

                    int result = SGP_ProcessNextIncomingMessage(SGKeepAlive_GetCurrentInterval(&_keepAliveAlgo));
                    
                    if (result == SGP_OK) continue;

                    if (result == SGP_ERR_TIMEOUT || result == SGP_ERR_IO) {
                        [_stateLock lock]; 
                        double oldVal = SGKeepAlive_GetCurrentInterval(&_keepAliveAlgo);
                        SGKeepAlive_ProcessHeartbeatResult(&_keepAliveAlgo, false); 
                        double newVal = SGKeepAlive_GetCurrentInterval(&_keepAliveAlgo);
                        BOOL isWiFi = _keepAliveAlgo.isWiFi;
                        [_stateLock unlock];
                        
                        if (newVal != oldVal) {
                            [[SGDatabaseManager sharedManager] saveKeepAliveInterval:newVal forWiFi:isWiFi];
                        }
                    }

                    if (result == SGP_ERR_AUTH) {
                        [self wipeProfileForReregistration];
                        uint32_t ra = SGP_GetLastDisconnectRetryAfter();
                        if (ra == 0xFFFFFFFF) {
                            [self transitionToState:SGStateErrorAuth];
                            dispatch_semaphore_wait(_wakeupSema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)SG_AUTH_FAILURE_BACKOFF_SECONDS * NSEC_PER_SEC));
                        }
                    } else if (result == SGP_ERR_REPLACED) {
                        wasReplaced = YES;
                    }
                    break;
                }
            }

            uint32_t retryAfter = SGP_GetLastDisconnectRetryAfter();
            SGP_DisconnectFromServer();

            [_stateLock lock]; if (_shouldDisconnect) break; [_stateLock unlock];

            if (wasReplaced) {
                uint32_t replaceDelay = (retryAfter > 0 && retryAfter != 0xFFFFFFFF) ? retryAfter : 1;
                [self transitionToState:SGStateBackingOff backoffSeconds:replaceDelay serverIP:ipCStr];
                dispatch_semaphore_wait(_wakeupSema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)replaceDelay * NSEC_PER_SEC));
                continue;
            }

            if (retryAfter == 0xFFFFFFFF) {
                [_stateLock lock]; _shouldDisconnect = YES; [_stateLock unlock];
                break;
            }

            [_stateLock lock]; failures = ++_consecutiveFailures; [_stateLock unlock];
            int delay = MIN((int)MAX((uint32_t)MIN(backoff + jitter, SG_MAX_BACKOFF_SECONDS), retryAfter), SG_MAX_BACKOFF_SECONDS);
            [self transitionToState:SGStateBackingOff backoffSeconds:(uint32_t)delay serverIP:ipCStr];
            dispatch_semaphore_wait(_wakeupSema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)delay * NSEC_PER_SEC));
        }
    }

loop_exit:
    [_stateLock lock]; _isRunning = NO; [_stateLock unlock];
    dispatch_semaphore_signal(_loopExitSema);
}

- (void)wipeProfileForReregistration {
    @autoreleasepool {
        NSString *profilePath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
        NSMutableDictionary *profile = [NSMutableDictionary dictionaryWithContentsOfFile:profilePath] ?: [NSMutableDictionary dictionary];
        [profile removeObjectForKey:@"device_address"];
        [profile removeObjectForKey:@"privateKey"];
        [profile writeToFile:profilePath atomically:YES];
        [[SGDatabaseManager sharedManager] resetAllTokensToRequireUpload];
    }
}

- (NSString *)getClientAddress {
    id addr = [[NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist"] objectForKey:@"device_address"];
    return [addr isKindOfClass:[NSString class]] ? addr : nil;
}

- (NSString *)getServerPubKey {
    id pubKey = [[NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist"] objectForKey:@"server_pub_key"];
    return [pubKey isKindOfClass:[NSString class]] ? pubKey : nil;
}

@end