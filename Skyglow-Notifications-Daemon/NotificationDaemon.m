#import "NotificationDaemon.h"
#import "Globals.h"
#import "ServerLocationFinder.h"
#import "GrowthAlgorithm.h"
#import "LocalIPC.h"
#include "PayloadParser.h"
#import "CryptoManager.h"
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <stdatomic.h>

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

@implementation NotificationDaemon {
    NSLock                *_stateLock;
    BOOL                   _isRunning;
    BOOL                   _shouldDisconnect;
    int                    _consecutiveFailures;
    dispatch_semaphore_t   _loopExitSema;
    dispatch_semaphore_t   _wakeupSema;
    SGPKeepAliveAlgorithm  _keepAliveAlgo;
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

- (void)transitionToState:(SGState)newState {
    [self transitionToState:newState backoffSec:0 serverIP:NULL];
}

- (void)transitionToState:(SGState)newState backoffSec:(uint32_t)backoffSec serverIP:(const char *)serverIP {
    SGStatusPayload current;
    StatusServer_current(&current);
    SGState currentState = (SGState)current.state;

    if (!isLegalTransition(currentState, newState)) {
        NSLog(@"[FSM] ⚠️  ILLEGAL TRANSITION: %s → %s", SGState_name(currentState), SGState_name(newState));
    }

    [_stateLock lock];
    int failures = _consecutiveFailures;
    [_stateLock unlock];

    const char *ip = serverIP;
    NSString *currentIPStr = GetServerIPString();
    if (!ip && currentIPStr) ip = [currentIPStr UTF8String];

    NSLog(@"[FSM] %s → %s  (failures=%d, backoff=%us)", SGState_name(currentState), SGState_name(newState), failures, backoffSec);
    StatusServer_post(newState, (uint32_t)failures, backoffSec, ip);
}

- (void)handleWelcomeMessage {
    NSString *clientAddress = [self getClientAddress];

    if (!clientAddress || [clientAddress length] == 0) {
        [self transitionToState:SGStateRegistering];
        NSString *proposed = startRegistration();
        if (!proposed) [self transitionToState:SGStateBackingOff];
        return;
    }

    RSA *privKey = getClientPrivKey();
    if (!privKey) {
        [self transitionToState:SGStateErrorBadConfig];
        [_stateLock lock]; _shouldDisconnect = YES; [_stateLock unlock];
        return;
    }

    NSString *language = [[NSLocale preferredLanguages] firstObject] ?: @"en";
    startLogin(clientAddress, privKey, language);
}

- (void)authenticationSuccessful {
    [_stateLock lock];
    _consecutiveFailures = 0;
    [_stateLock unlock];

    [self transitionToState:SGStateConnected];

    NSString *currentAddr = GetServerAddress();
    if (currentAddr) {
        [ServerLocationFinder refreshDNSCacheAsync:currentAddr];
    }

    flushPendingACKs();
    flushActiveTopicFilter();
    [self uploadPendingTokensAsync];
}

- (void)uploadPendingTokensAsync {
    NSArray *pending = [db pendingUploadTokens];
    if ([pending count] == 0) return;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        for (NSDictionary *entry in pending) {
            @autoreleasepool {
                NSData   *routingKey = entry[@"routingKey"];
                NSString *bundleID   = entry[@"bundleID"];

                if (!isConnected()) break;

                if (registerDeviceToken(routingKey, bundleID)) {
                    [db markTokenUploaded:routingKey];
                }
            }
        }
    });
}

- (void)processNotificationMessage:(NSDictionary *)messageDict {
    @autoreleasepool {
        NSData *msgID = messageDict[@"msg_id"];
        if (!msgID || [msgID length] != SGP_MSG_ID_LEN) return;

        // ── 1. Deduplication Check ──────────────────────────────────
        @synchronized(_seenMessageIDs) {
            if ([_seenMessageIDs containsObject:msgID]) {
                NSLog(@"[Daemon] ♻️ Duplicate message received, silently ACKing");
                ackNotification(msgID, 0);
                return; 
            }
            [_seenMessageIDs addObject:msgID];
            if ([_seenMessageIDs count] > 200) [_seenMessageIDs removeObjectAtIndex:0];
        }

        // ── 2. Power Assertion (Keep CPU Awake) ─────────────────────
        __block _Atomic IOPMAssertionID assertionID = 0;
        IOPMAssertionID tempID = 0;
        
        if (IOPMAssertionCreateWithName(kIOPMAssertionTypePreventUserIdleSystemSleep, 
                                        kIOPMAssertionLevelOn, 
                                        CFSTR("com.skyglow.snd.processing"), 
                                        &tempID) == kIOReturnSuccess) {
            atomic_store(&assertionID, tempID);
            
            // Failsafe timeout
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                IOPMAssertionID expected = tempID;
                if (atomic_compare_exchange_strong(&assertionID, &expected, 0)) {
                    IOPMAssertionRelease(expected);
                    NSLog(@"[Daemon] ⚠️ Power assertion timed out and was forcibly released.");
                }
            });
        }

        // ── 3. Decrypt & Parse ──────────────────────────────────────
        NSData *routingKey = messageDict[@"routing_key"];
        NSDictionary *routingData = [db dataForRoutingKey:routingKey];
        if (!routingData) goto cleanup_assertion;

        NSData *payloadBytes = messageDict[@"data"];
        if (!payloadBytes) { ackNotification(msgID, 2); goto cleanup_assertion; }

        if ([messageDict[@"is_encrypted"] boolValue]) {
            NSData *iv = messageDict[@"iv"];
            if (!iv) { ackNotification(msgID, 1); goto cleanup_assertion; }
            
            payloadBytes = decryptAESGCM(payloadBytes, routingData[@"e2eeKey"], iv, nil);
            if (!payloadBytes) { ackNotification(msgID, 1); goto cleanup_assertion; }
        }

        NSDictionary *parsed = SGP_ParseBinaryPayload((const uint8_t *)payloadBytes.bytes, (uint32_t)payloadBytes.length);
        if (!parsed || parsed.count == 0) {
            ackNotification(msgID, 2);
            goto cleanup_assertion;
        }

        NSLog(@"[Daemon] Received Notification for %@", routingData[@"bundleID"]);
        LocalIPC_SendPush(routingData[@"bundleID"], parsed);
        ackNotification(msgID, 0);

cleanup_assertion:
        // ── 4. Release Power Assertion ──────────────────────────────
        {
            IOPMAssertionID current = atomic_exchange(&assertionID, 0);
            if (current != 0) {
                IOPMAssertionRelease(current);
            }
        }
    }
}

- (void)deviceTokenRegistrationCompleted:(NSString *)bundleId {
    (void)bundleId;
}

- (void)registrationCompleted:(NSString *)deviceAddress privateKey:(NSString *)privateKeyPEM serverVersion:(uint32_t)serverVersion {
    NSString *profilePath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
    NSMutableDictionary *profile = [NSMutableDictionary dictionaryWithContentsOfFile:profilePath];
    if (!profile) profile = [NSMutableDictionary dictionary];

    profile[@"device_address"] = deviceAddress;
    profile[@"privateKey"]     = privateKeyPEM;

    if (![profile writeToFile:profilePath atomically:YES]) {
        [self transitionToState:SGStateError];
        [_stateLock lock]; _shouldDisconnect = YES; [_stateLock unlock];
        return;
    }

    [db resetAllTokensNeedUpload];

    BIO *bio = BIO_new_mem_buf((void *)[privateKeyPEM UTF8String], -1);
    RSA *privKey = bio ? PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL) : NULL;
    if (bio) BIO_free(bio);

    if (!privKey) {
        [self transitionToState:SGStateError];
        [_stateLock lock]; _shouldDisconnect = YES; [_stateLock unlock];
        return;
    }

    [self transitionToState:SGStateAuthenticating];
    startLogin(deviceAddress, privKey, [[NSLocale preferredLanguages] firstObject] ?: @"en");
}

- (void)registrationFailed:(uint8_t)reasonCode reason:(NSString *)reason {
    NSLog(@"[Daemon] Registration failed: code=0x%02X reason=%@", reasonCode, reason);
}

- (void)handleConfigReload {
    @autoreleasepool {
        NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
        NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];

        if (!prefs || ![[prefs objectForKey:@"enabled"] boolValue]) {
            [self requestDisconnect];
            [self transitionToState:SGStateDisabled];
            return;
        }

        NSString *profilePath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
        NSDictionary *profile = [NSDictionary dictionaryWithContentsOfFile:profilePath];
        NSString *newServerAddr = profile[@"server_address"];

        if (![newServerAddr isKindOfClass:[NSString class]] || [newServerAddr length] == 0) {
            [self requestDisconnect];
            [self transitionToState:SGStateIdleUnregistered];
            return;
        }

        if ([newServerAddr isEqualToString:GetServerAddress()]) return;

        [self requestDisconnect];
        dispatch_semaphore_wait(_loopExitSema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));

        SetServerAddress(newServerAddr);
        [self transitionToState:SGStateResolvingDNS];

        NSDictionary *txt = nil;
        for (int attempt = 1; attempt <= DNS_RETRY_COUNT; attempt++) {
            txt = [ServerLocationFinder resolveServerLocation:newServerAddr];
            if (txt) break;
            if (attempt < DNS_RETRY_COUNT) sleep(DNS_RETRY_DELAY_SEC);
        }

        if (!txt) {
            [self transitionToState:SGStateIdleDNSFailed];
            return;
        }

        SetServerIPString(txt[@"tcp_addr"]);
        SetServerPortString(txt[@"tcp_port"]);
    }
}

- (void)networkBecameReachable:(BOOL)isWWAN {
    [_stateLock lock];
    BOOL alreadyRunning = _isRunning;
    if (!alreadyRunning) {
        _isRunning = YES;
        _shouldDisconnect = NO;
    }
    _consecutiveFailures = 0;
    SGPAlgorithm_Init(&_keepAliveAlgo, !isWWAN); 
    [_stateLock unlock];

    dispatch_semaphore_signal(_wakeupSema);

    if (!alreadyRunning) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [self connectionLoop];
        });
    }
}

- (void)keepAlivePingSucceeded {
    [_stateLock lock];
    SGPAlgorithm_ProcessAction(&_keepAliveAlgo, true);
    [_stateLock unlock];
}

- (void)requestDisconnect {
    [_stateLock lock];
    _shouldDisconnect = YES;
    [_stateLock unlock];
    sendClientDisconnect();
    disconnectFromServer();
    dispatch_semaphore_signal(_wakeupSema);
}

- (void)connectionLoop {
    [_stateLock lock];
    if (_isRunning) { [_stateLock unlock]; return; }
    _isRunning = YES;
    [_stateLock unlock];

    while (dispatch_semaphore_wait(_wakeupSema, DISPATCH_TIME_NOW) == 0) {}

    NSString *pubKey = [self getServerPubKey];
    NSString *currentPortStr = GetServerPortString();
    
    if (!isValidPort(currentPortStr) || !pubKey || [pubKey length] == 0) {
        [self transitionToState:SGStateErrorBadConfig];
        goto loop_exit;
    }
    int serverPort = [currentPortStr intValue];

    {
        while (1) {
            @autoreleasepool {
                [_stateLock lock];
                BOOL stop = _shouldDisconnect;
                int failures = _consecutiveFailures;
                [_stateLock unlock];
                
                if (stop) break;

                NSString *currentIPStr = GetServerIPString();
                const char *ipCStr = currentIPStr ? [currentIPStr UTF8String] : "";

                if (failures >= MAX_CONSECUTIVE_FAILURES) {
                    [self transitionToState:SGStateIdleCircuitOpen backoffSec:CIRCUIT_OPEN_WAIT_SEC serverIP:ipCStr];
                    dispatch_semaphore_wait(_wakeupSema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)CIRCUIT_OPEN_WAIT_SEC * NSEC_PER_SEC));
                    [_stateLock lock]; _consecutiveFailures = 0; [_stateLock unlock];
                    continue;
                }

                int backoff = INITIAL_BACKOFF_SEC;
                for (int i = 0; i < failures && backoff < MAX_BACKOFF_SEC; i++) {
                    backoff = MIN(backoff * 2, MAX_BACKOFF_SEC);
                }
                int jitter = (int)(arc4random_uniform(MAX_JITTER_SEC + 1));

                [self transitionToState:SGStateConnecting backoffSec:0 serverIP:ipCStr];

                setNotificationDelegate(self);
                int cr = connectToServer(ipCStr, serverPort, pubKey);

                if (cr != 0) {
                    [_stateLock lock]; failures = ++_consecutiveFailures; [_stateLock unlock];
                    int delay = MIN(backoff + jitter, MAX_BACKOFF_SEC);
                    [self transitionToState:SGStateBackingOff backoffSec:(uint32_t)delay serverIP:ipCStr];
                    dispatch_semaphore_wait(_wakeupSema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)delay * NSEC_PER_SEC));
                    continue;
                }

                [self transitionToState:SGStateAuthenticating];
                BOOL wasReplaced = NO;

                while (1) {
                    @autoreleasepool {
                        [_stateLock lock]; BOOL stopInner = _shouldDisconnect; [_stateLock unlock];
                        if (stopInner) break;

                        double currentInterval = SGPAlgorithm_GetInterval(&_keepAliveAlgo);
                        int result = handleMessage(currentInterval);
                        
                        if (result == SGP_OK) continue;

                        if (result == SGP_ERR_TIMEOUT || result == SGP_ERR_IO) {
                            [_stateLock lock]; SGPAlgorithm_ProcessAction(&_keepAliveAlgo, false); [_stateLock unlock];
                        }

                        if (result == SGP_ERR_AUTH) {
                            [_stateLock lock]; BOOL intentional = _shouldDisconnect; [_stateLock unlock];
                            if (intentional) break;

                            uint32_t ra = getLastDisconnRetryAfter();
                            if (ra == SGP_DISCONNECT_NO_RETRY) {
                                [self transitionToState:SGStateErrorAuth];
                                [self wipeProfileForReregistration];
                                dispatch_semaphore_wait(_wakeupSema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)LONG_AUTH_FAIL_BACKOFF_SEC * NSEC_PER_SEC));
                            } else {
                                [self wipeProfileForReregistration];
                            }
                        } else if (result == SGP_ERR_REPLACED) {
                            wasReplaced = YES;
                        }
                        break;
                    }
                }

                uint32_t retryAfter = getLastDisconnRetryAfter();
                sendClientDisconnect();
                disconnectFromServer();

                [_stateLock lock]; BOOL hardStop = _shouldDisconnect; [_stateLock unlock];
                if (hardStop) break;

                if (wasReplaced) {
                    uint32_t replaceDelay = (retryAfter > 0 && retryAfter != SGP_DISCONNECT_NO_RETRY) ? retryAfter : 1;
                    [self transitionToState:SGStateBackingOff backoffSec:replaceDelay serverIP:ipCStr];
                    dispatch_semaphore_wait(_wakeupSema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)replaceDelay * NSEC_PER_SEC));
                    continue;
                }

                if (retryAfter == SGP_DISCONNECT_NO_RETRY) {
                    [_stateLock lock]; _shouldDisconnect = YES; [_stateLock unlock];
                    break;
                }

                [_stateLock lock]; failures = ++_consecutiveFailures; [_stateLock unlock];

                int delay = MIN((int)MAX((uint32_t)MIN(backoff + jitter, MAX_BACKOFF_SEC), retryAfter), MAX_BACKOFF_SEC);
                [self transitionToState:SGStateBackingOff backoffSec:(uint32_t)delay serverIP:ipCStr];
                dispatch_semaphore_wait(_wakeupSema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)delay * NSEC_PER_SEC));
            }
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
        [profile removeObjectForKey:@"private_key"];
        [profile writeToFile:profilePath atomically:YES];
        [db resetAllTokensNeedUpload];
    }
}

- (NSString *)getClientAddress {
    return [[NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist"] objectForKey:@"device_address"];
}

- (NSString *)getServerPubKey {
    return [[NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist"] objectForKey:@"server_pub_key"];
}

@end