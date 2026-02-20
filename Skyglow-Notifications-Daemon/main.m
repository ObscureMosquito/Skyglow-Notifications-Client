#import "main.h"
#include "ServerLocationFinder.h"
#include "Protocol.h"
#include <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#import "CryptoManager.h"
#import "DBManager.h"
#import "TweakMachMessages.h"
#include <bootstrap.h>
#import "Globals.h"
#include <signal.h>
#include <stdatomic.h>

/* ─────────────────────────────────────────────────────────────────
 * DNS cache max age
 * ───────────────────────────────────────────────────────────────── */

#define DNS_CACHE_MAX_AGE_SECONDS   3600.0

/* ─────────────────────────────────────────────────────────────────
 * Globals
 * ───────────────────────────────────────────────────────────────── */

NSString *serverAddress    = nil;   // e.g. @"sgn.example.com"
DBManager *db              = nil;
NSString *serverIPString   = nil;   // resolved IP, set before threads start
NSString *serverPortString = nil;   // resolved port, set before threads start

// Retained reference so the reachability and config-reload callbacks
// can reach the daemon. Set once in main(), never mutated after that.
static NotificationDaemon *gDaemon = nil;

/* ─────────────────────────────────────────────────────────────────
 * FSM transition table
 *
 * Defines every legal (from → to) pair. Any transition not in this
 * table is a bug. transitionToState: logs a fault on illegal moves
 * but does not crash — a daemon that logs and continues is better
 * than a daemon that stops delivering disaster alerts.
 *
 * SGStateShuttingDown is always a legal destination (handled inline).
 * SGStateStarting as a source is always legal (first real transition).
 * ───────────────────────────────────────────────────────────────── */

typedef struct { SGState from; SGState to; } SGTransition;

static const SGTransition kLegalTransitions[] = {
    // ── Startup ──────────────────────────────────────────────────
    { SGStateStarting,          SGStateDisabled            },
    { SGStateStarting,          SGStateIdleUnregistered    },
    { SGStateStarting,          SGStateResolvingDNS        },
    { SGStateStarting,          SGStateIdleDNSFailed       },
    { SGStateStarting,          SGStateIdleNoNetwork       },
    { SGStateStarting,          SGStateError               },
    { SGStateStarting,          SGStateErrorBadConfig      },

    // ── DNS resolution ───────────────────────────────────────────
    { SGStateResolvingDNS,      SGStateConnecting          },
    { SGStateResolvingDNS,      SGStateIdleDNSFailed       },
    { SGStateResolvingDNS,      SGStateErrorBadConfig      },

    // ── DNS failed ───────────────────────────────────────────────
    { SGStateIdleDNSFailed,     SGStateResolvingDNS        },
    { SGStateIdleDNSFailed,     SGStateDisabled            },

    // ── No network ───────────────────────────────────────────────
    { SGStateIdleNoNetwork,     SGStateConnecting          },
    { SGStateIdleNoNetwork,     SGStateDisabled            },
    { SGStateIdleNoNetwork,     SGStateResolvingDNS        },

    // ── Not registered ───────────────────────────────────────────
    { SGStateIdleUnregistered,  SGStateResolvingDNS        },
    { SGStateIdleUnregistered,  SGStateDisabled            },

    // ── Connecting ───────────────────────────────────────────────
    { SGStateConnecting,        SGStateAuthenticating      },
    { SGStateConnecting,        SGStateBackingOff          },
    { SGStateConnecting,        SGStateIdleNoNetwork       },
    { SGStateConnecting,        SGStateIdleCircuitOpen     },
    { SGStateConnecting,        SGStateErrorBadConfig      },

    // ── Authenticating ───────────────────────────────────────────
    { SGStateAuthenticating,    SGStateConnected           },
    { SGStateAuthenticating,    SGStateBackingOff          },
    { SGStateAuthenticating,    SGStateErrorAuth           },

    // ── Connected ────────────────────────────────────────────────
    { SGStateConnected,         SGStateBackingOff          },
    { SGStateConnected,         SGStateIdleNoNetwork       },
    { SGStateConnected,         SGStateDisabled            },
    { SGStateConnected,         SGStateResolvingDNS        },

    // ── Backing off ───────────────────────────────────────────────
    { SGStateBackingOff,        SGStateConnecting          },
    { SGStateBackingOff,        SGStateIdleNoNetwork       },
    { SGStateBackingOff,        SGStateIdleCircuitOpen     },
    { SGStateBackingOff,        SGStateDisabled            },

    // ── Circuit open ──────────────────────────────────────────────
    { SGStateIdleCircuitOpen,   SGStateConnecting          },
    { SGStateIdleCircuitOpen,   SGStateIdleNoNetwork       },
    { SGStateIdleCircuitOpen,   SGStateDisabled            },
    { SGStateIdleCircuitOpen,   SGStateResolvingDNS        },

    // ── Auth error ────────────────────────────────────────────────
    { SGStateErrorAuth,         SGStateDisabled            },
    { SGStateErrorAuth,         SGStateResolvingDNS        },

    // ── Bad config ────────────────────────────────────────────────
    { SGStateErrorBadConfig,    SGStateDisabled            },
    { SGStateErrorBadConfig,    SGStateResolvingDNS        },

    // ── Disabled ─────────────────────────────────────────────────
    { SGStateDisabled,          SGStateResolvingDNS        },
    { SGStateDisabled,          SGStateIdleUnregistered    },
};

static const size_t kLegalTransitionCount =
    sizeof(kLegalTransitions) / sizeof(kLegalTransitions[0]);

static BOOL isLegalTransition(SGState from, SGState to) {
    if (to   == SGStateShuttingDown) return YES;
    if (from == SGStateStarting)     return YES;
    for (size_t i = 0; i < kLegalTransitionCount; i++) {
        if (kLegalTransitions[i].from == from &&
            kLegalTransitions[i].to   == to) {
            return YES;
        }
    }
    return NO;
}

/* ─────────────────────────────────────────────────────────────────
 * OpenSSL one-time initialization
 * ───────────────────────────────────────────────────────────────── */

static void initOpenSSLOnce(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
    });
}

/* ─────────────────────────────────────────────────────────────────
 * SendPush — forward a notification to the SpringBoard Mach service
 * ───────────────────────────────────────────────────────────────── */

static kern_return_t SendPush(NSString *topic, NSDictionary *userInfo) {
    if (!topic || [topic length] == 0) {
        NSLog(@"[SendPush] Missing topic");
        return KERN_INVALID_ARGUMENT;
    }

    NSData *topicData = [topic dataUsingEncoding:NSUTF8StringEncoding
                           allowLossyConversion:NO];
    if (!topicData || topicData.length == 0) {
        NSLog(@"[SendPush] Topic UTF-8 conversion failed");
        return KERN_INVALID_ARGUMENT;
    }

    NSData *plistData = nil;
    if (userInfo) {
        NSError *err = nil;
        plistData = [NSPropertyListSerialization dataWithPropertyList:userInfo
                                                             format:NSPropertyListBinaryFormat_v1_0
                                                            options:0
                                                              error:&err];
        if (!plistData) {
            NSLog(@"[SendPush] Payload serialization failed: %@", err);
            return KERN_INVALID_ARGUMENT;
        }
    } else {
        plistData = [NSData data];
    }

    mach_port_t bootstrapPort = MACH_PORT_NULL;
    kern_return_t kr = task_get_bootstrap_port(mach_task_self(), &bootstrapPort);
    if (kr != KERN_SUCCESS || bootstrapPort == MACH_PORT_NULL) {
        NSLog(@"[SendPush] task_get_bootstrap_port: %s", mach_error_string(kr));
        return (kr == KERN_SUCCESS) ? KERN_FAILURE : kr;
    }

    mach_port_t servicePort = MACH_PORT_NULL;
    kr = bootstrap_look_up(bootstrapPort, SKYGLOW_MACH_SERVICE_NAME_PUSH, &servicePort);
    if (kr != KERN_SUCCESS || servicePort == MACH_PORT_NULL) {
        NSLog(@"[SendPush] bootstrap_look_up(%s): %s",
              SKYGLOW_MACH_SERVICE_NAME_PUSH, mach_error_string(kr));
        return (kr == KERN_SUCCESS) ? KERN_FAILURE : kr;
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winvalid-offsetof"
    const size_t maxInline = sizeof(((MachPushRequestMessage *)0)->userInfoData);
#pragma clang diagnostic pop

    if ((size_t)plistData.length > maxInline) {
        NSLog(@"[SendPush] Payload too large (%lu > %lu)",
              (unsigned long)plistData.length, (unsigned long)maxInline);
        return KERN_RESOURCE_SHORTAGE;
    }

    MachPushRequestMessage msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_remote_port = servicePort;
    msg.header.msgh_id          = SKYGLOW_REQUEST_PUSH;
    msg.body.msgh_descriptor_count = 0;
    msg.type                    = SKYGLOW_REQUEST_PUSH;

    size_t maxTopic = sizeof(msg.topic) - 1;
    size_t copyLen  = MIN((size_t)topicData.length, maxTopic);
    memcpy(msg.topic, topicData.bytes, copyLen);
    msg.topic[copyLen] = '\0';

    msg.userInfoLength = (uint32_t)plistData.length;
    if (plistData.length > 0) {
        memcpy(msg.userInfoData, plistData.bytes, plistData.length);
    }

    size_t usedSize = offsetof(MachPushRequestMessage, userInfoData) + plistData.length;
    usedSize = (usedSize + 3) & ~(size_t)3;
    if (usedSize > sizeof(msg)) {
        NSLog(@"[SendPush] Size overflow (%zu)", usedSize);
        return KERN_INVALID_ARGUMENT;
    }
    msg.header.msgh_size = (mach_msg_size_t)usedSize;

    kr = mach_msg(&msg.header, MACH_SEND_MSG, msg.header.msgh_size, 0,
                  MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[SendPush] mach_msg failed: %s (%d)", mach_error_string(kr), kr);
    }
    return kr;
}

/* ─────────────────────────────────────────────────────────────────
 * DNS resolution with caching
 * ───────────────────────────────────────────────────────────────── */

static NSDictionary *resolveServerLocation(NSString *serverAddr) {
    NSString *dnsName = [@"_sgn." stringByAppendingString:serverAddr];

    NSDictionary *cached = [db cachedDNSForDomain:dnsName
                                    maxAgeSeconds:DNS_CACHE_MAX_AGE_SECONDS];
    if (cached) {
        NSLog(@"[Main] Using cached DNS for %@", dnsName);
        return cached;
    }

    NSLog(@"[Main] Cache miss — live DNS lookup for %@", dnsName);
    NSDictionary *txt = QueryServerLocation(dnsName);
    if (!txt) return nil;

    NSString *ip   = txt[@"tcp_addr"];
    NSString *port = txt[@"tcp_port"];
    if (ip && port) {
        [db storeDNSCache:dnsName ip:ip port:port];
        NSLog(@"[Main] Cached DNS: %@ -> %@:%@", dnsName, ip, port);
    }
    return txt;
}

static void refreshDNSCacheAsync(NSString *serverAddr) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
        @autoreleasepool {
            NSString *dnsName = [@"_sgn." stringByAppendingString:serverAddr];
            NSDictionary *txt = QueryServerLocation(dnsName);
            if (txt) {
                NSString *ip   = txt[@"tcp_addr"];
                NSString *port = txt[@"tcp_port"];
                if (ip && port) {
                    [db storeDNSCache:dnsName ip:ip port:port];
                    NSLog(@"[Main] DNS cache refreshed: %@:%@", ip, port);
                }
            }
        }
    });
}

/* ─────────────────────────────────────────────────────────────────
 * Validation helpers
 * ───────────────────────────────────────────────────────────────── */

static BOOL isValidIPAddress(NSString *ip) {
    if (!ip) return NO;
    struct sockaddr_in sa;
    return inet_pton(AF_INET, [ip UTF8String], &sa.sin_addr) == 1;
}

static BOOL isValidPort(NSString *port) {
    if (!port || [port length] == 0) return NO;
    NSCharacterSet *nonDigits = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
    if ([port rangeOfCharacterFromSet:nonDigits].location != NSNotFound) return NO;
    int p = [port intValue];
    return (p > 0 && p <= 65535);
}

/* ─────────────────────────────────────────────────────────────────
 * Reachability callback
 * ───────────────────────────────────────────────────────────────── */

static void ReachabilityCallback(SCNetworkReachabilityRef target,
                                  SCNetworkReachabilityFlags flags,
                                  void *info) {
    (void)target;
    BOOL reachable    = (flags & kSCNetworkFlagsReachable) != 0;
    BOOL needsConn    = (flags & kSCNetworkFlagsConnectionRequired) != 0;
    BOOL reachableNow = reachable && !needsConn;

    NotificationDaemon *daemon = (__bridge NotificationDaemon *)info;

    if (reachableNow) {
        NSLog(@"[Reachability] Network reachable");
        [daemon networkBecameReachable];
    } else {
        NSLog(@"[Reachability] Network unreachable");
        [daemon transitionToState:SGStateIdleNoNetwork];
    }
}

/* ─────────────────────────────────────────────────────────────────
 * NotificationDaemon
 * ───────────────────────────────────────────────────────────────── */

@implementation NotificationDaemon {
    /// Guards _isRunning, _shouldDisconnect, and _consecutiveFailures.
    /// These are accessed from the connection thread, the reachability
    /// callback thread, and handleConfigReload. Always take this lock
    /// for reads and writes of those three variables.
    NSLock               *_stateLock;

    /// YES while the connection loop thread is executing.
    /// Prevents duplicate loops from being spawned by rapid callbacks.
    BOOL                  _isRunning;

    /// Set by requestDisconnect. The connection loop checks this at
    /// each iteration boundary and exits cleanly when YES.
    BOOL                  _shouldDisconnect;

    /// Consecutive connection failures since last clean connect.
    /// Persists across attempts within one run so backoff accumulates.
    int                   _consecutiveFailures;

    /// SCNetworkReachability ref. Created in startMonitoringNetworkReachability,
    /// released in dealloc.
    SCNetworkReachabilityRef _reachabilityRef;

    /// Signalled by connectionLoop when _isRunning is set to NO.
    /// handleConfigReload waits on this before mutating shared globals
    /// (serverIPString, serverPortString) to guarantee no data race.
    dispatch_semaphore_t  _loopExitSema;
}

- (id)init {
    if ((self = [super init])) {
        _stateLock           = [[NSLock alloc] init];
        _isRunning           = NO;
        _shouldDisconnect    = NO;
        _consecutiveFailures = 0;
        _loopExitSema        = dispatch_semaphore_create(0);
    }
    return self;
}

- (void)dealloc {
    if (_reachabilityRef) {
        SCNetworkReachabilitySetCallback(_reachabilityRef, NULL, NULL);
        SCNetworkReachabilitySetDispatchQueue(_reachabilityRef, NULL);
        CFRelease(_reachabilityRef);
        _reachabilityRef = NULL;
    }
    [_stateLock release];
    dispatch_release(_loopExitSema);
    [super dealloc];
}

/* ── State machine ──────────────────────────────────────────────── */

- (void)transitionToState:(SGState)newState {
    [self transitionToState:newState backoffSec:0 serverIP:NULL];
}

- (void)transitionToState:(SGState)newState
               backoffSec:(uint32_t)backoffSec
                 serverIP:(const char *)serverIP {

    SGStatusPayload current;
    StatusServer_current(&current);
    SGState currentState = (SGState)current.state;

    if (!isLegalTransition(currentState, newState)) {
        NSLog(@"[FSM] ⚠️  ILLEGAL TRANSITION: %s → %s",
              SGState_name(currentState), SGState_name(newState));
        // Do not drop the transition — log and proceed.
    }

    [_stateLock lock];
    int failures = _consecutiveFailures;
    [_stateLock unlock];

    const char *ip = serverIP;
    if (!ip && serverIPString) ip = [serverIPString UTF8String];

    NSLog(@"[FSM] %s → %s  (failures=%d, backoff=%us)",
          SGState_name(currentState), SGState_name(newState), failures, backoffSec);

    StatusServer_post(newState, (uint32_t)failures, backoffSec, ip);
}

/* ── NotificationDelegate ───────────────────────────────────────── */

- (void)handleWelcomeMessage {
    NSString *clientAddress = [self getClientAddress];
    RSA *privKey = getClientPrivKey();

    if (!clientAddress || !privKey) {
        NSLog(@"[Daemon] Missing credentials for login");
        if (privKey) RSA_free(privKey);
        return;
    }

    NSString *language = [[NSLocale preferredLanguages] firstObject] ?: @"en";
    // privKey ownership transfers to Protocol.m; freed in disconnectFromServer().
    startLogin(clientAddress, privKey, language);
}

- (void)authenticationSuccessful {
    [_stateLock lock];
    _consecutiveFailures = 0;
    [_stateLock unlock];

    [self transitionToState:SGStateConnected];

    if (serverAddress) {
        refreshDNSCacheAsync(serverAddress);
    }
}

- (void)processNotificationMessage:(NSDictionary *)messageDict {
    @autoreleasepool {
        // ── SGP/2 dict keys (set by Protocol.m) ──────────────────
        // @"routing_key"  NSData (32 bytes)
        // @"msg_id"       NSData (16 bytes)   ← raw bytes, NOT a UUID string
        // @"is_encrypted" NSNumber (BOOL)
        // @"data_type"    NSString  @"json" or @"plist"
        // @"data"         NSData    ciphertext||tag  OR  raw notification bytes
        // @"iv"           NSData (12 bytes)   present only when is_encrypted=YES

        NSData *routingKey = messageDict[@"routing_key"];
        if (!routingKey || [routingKey length] != SGP_ROUTING_KEY_LEN) {
            NSLog(@"[Daemon] Notification missing or malformed routing_key");
            return;
        }

        NSDictionary *routingData = [db dataForRoutingKey:routingKey];
        if (!routingData) {
            NSLog(@"[Daemon] No routing data for routing_key");
            return;
        }

        NSString *bundleID = routingData[@"bundleID"];
        NSData   *msgID    = messageDict[@"msg_id"];
        if (!msgID || [msgID length] != SGP_MSG_ID_LEN) {
            NSLog(@"[Daemon] Notification missing or malformed msg_id");
            return;
        }

        NSDictionary *userInfo = nil;

        if ([messageDict[@"is_encrypted"] boolValue]) {
            NSString *outputType = messageDict[@"data_type"];
            NSData   *ciphertext = messageDict[@"data"];   // ciphertext||GCM tag
            NSData   *iv         = messageDict[@"iv"];

            if (!ciphertext || !iv) {
                NSLog(@"[Daemon] Encrypted notification missing data/iv");
                ackNotification(msgID, 1);
                return;
            }

            NSData *decrypted = decryptAESGCM(ciphertext,
                                              routingData[@"e2eeKey"],
                                              iv, nil);
            if (!decrypted) {
                NSLog(@"[Daemon] Decryption failed");
                ackNotification(msgID, 1);
                return;
            }

            NSError *error = nil;
            if ([outputType isEqualToString:@"json"]) {
                userInfo = [NSJSONSerialization JSONObjectWithData:decrypted
                                                          options:0
                                                            error:&error];
            } else if ([outputType isEqualToString:@"plist"]) {
                userInfo = [NSPropertyListSerialization
                            propertyListWithData:decrypted
                                        options:NSPropertyListImmutable
                                         format:nil
                                          error:&error];
            } else {
                NSLog(@"[Daemon] Unknown data_type: %@", outputType);
                ackNotification(msgID, 2);
                return;
            }

            if (!userInfo) {
                NSLog(@"[Daemon] Deserialisation failed: %@", error);
                ackNotification(msgID, 2);
                return;
            }
        } else {
            // Plaintext path: @"data" contains raw bytes that must still
            // be deserialised into an NSDictionary for SendPush.
            NSData   *rawData   = messageDict[@"data"];
            NSString *dataType  = messageDict[@"data_type"];
            NSError  *error     = nil;

            if (!rawData) {
                NSLog(@"[Daemon] Plaintext notification missing data");
                ackNotification(msgID, 2);
                return;
            }

            if ([dataType isEqualToString:@"json"]) {
                userInfo = [NSJSONSerialization JSONObjectWithData:rawData
                                                          options:0
                                                            error:&error];
            } else {
                userInfo = [NSPropertyListSerialization
                            propertyListWithData:rawData
                                        options:NSPropertyListImmutable
                                         format:nil
                                          error:&error];
            }

            if (!userInfo) {
                NSLog(@"[Daemon] Plaintext deserialisation failed: %@", error);
                ackNotification(msgID, 2);
                return;
            }
        }

        SendPush(bundleID, userInfo);
        ackNotification(msgID, 0);
    }
}

- (void)deviceTokenRegistrationCompleted:(NSString *)bundleId {
    // Semaphore in Protocol.m handles the synchronous wait.
    (void)bundleId;
}

/* ── Config reload ──────────────────────────────────────────────── */

- (void)handleConfigReload {
    NSLog(@"[Daemon] Config reload triggered");

    @autoreleasepool {
        NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
        NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];

        if (!prefs || ![[prefs objectForKey:@"enabled"] boolValue]) {
            NSLog(@"[Daemon] Config reload: disabled");
            [self requestDisconnect];
            [self transitionToState:SGStateDisabled];
            return;
        }

        NSString *profilePath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
        NSDictionary *profile = [NSDictionary dictionaryWithContentsOfFile:profilePath];
        NSString *newServerAddr = profile[@"server_address"];

        if (![newServerAddr isKindOfClass:[NSString class]] || [newServerAddr length] == 0) {
            NSLog(@"[Daemon] Config reload: not registered");
            [self requestDisconnect];
            [self transitionToState:SGStateIdleUnregistered];
            return;
        }

        if ([newServerAddr isEqualToString:serverAddress]) {
            NSLog(@"[Daemon] Config reload: same server — nudging loop");
            [self networkBecameReachable];
            return;
        }

        // Server address changed. Disconnect and wait for the connection
        // loop to fully exit before mutating shared globals.
        NSLog(@"[Daemon] Config reload: server changed to %@", newServerAddr);
        [self requestDisconnect];

        long waited = dispatch_semaphore_wait(
            _loopExitSema,
            dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
        if (waited != 0) {
            NSLog(@"[Daemon] Config reload: loop exit timed out — proceeding");
        }

        [serverAddress release];
        serverAddress = [newServerAddr retain];

        [self transitionToState:SGStateResolvingDNS];

        NSDictionary *txt = nil;
        for (int attempt = 1; attempt <= DNS_RETRY_COUNT; attempt++) {
            txt = resolveServerLocation(newServerAddr);
            if (txt) break;
            if (attempt < DNS_RETRY_COUNT) sleep(DNS_RETRY_DELAY_SEC);
        }

        if (!txt) {
            NSLog(@"[Daemon] Config reload: DNS failed for %@", newServerAddr);
            [self transitionToState:SGStateIdleDNSFailed];
            return;
        }

        NSString *ip   = txt[@"tcp_addr"];
        NSString *port = txt[@"tcp_port"];

        if (!isValidIPAddress(ip) || !isValidPort(port)) {
            NSLog(@"[Daemon] Config reload: bad IP/port from DNS");
            [self transitionToState:SGStateErrorBadConfig];
            return;
        }

        [serverIPString release];   serverIPString   = [ip retain];
        [serverPortString release]; serverPortString = [port retain];

        [self networkBecameReachable];
    }
}

/* ── Reachability ───────────────────────────────────────────────── */

- (void)startMonitoringNetworkReachability {
    struct sockaddr_in zeroAddress;
    memset(&zeroAddress, 0, sizeof(zeroAddress));
    zeroAddress.sin_len    = sizeof(zeroAddress);
    zeroAddress.sin_family = AF_INET;

    _reachabilityRef = SCNetworkReachabilityCreateWithAddress(
        NULL, (const struct sockaddr *)&zeroAddress);
    if (!_reachabilityRef) {
        NSLog(@"[Daemon] Failed to create reachability ref");
        return;
    }

    SCNetworkReachabilityContext ctx = {0, (__bridge void *)(self), NULL, NULL, NULL};
    if (!SCNetworkReachabilitySetCallback(_reachabilityRef, ReachabilityCallback, &ctx)) {
        NSLog(@"[Daemon] Could not set reachability callback");
        return;
    }

    dispatch_queue_t bgQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    if (!SCNetworkReachabilitySetDispatchQueue(_reachabilityRef, bgQueue)) {
        NSLog(@"[Daemon] Could not set reachability dispatch queue");
    }

    NSLog(@"[Daemon] Reachability monitoring started");
}

- (SCNetworkReachabilityFlags)getReachabilityFlags {
    SCNetworkReachabilityFlags flags = 0;
    if (_reachabilityRef) SCNetworkReachabilityGetFlags(_reachabilityRef, &flags);
    return flags;
}

- (void)networkBecameReachable {
    [_stateLock lock];
    BOOL alreadyRunning = _isRunning;
    [_stateLock unlock];

    if (alreadyRunning) {
        NSLog(@"[Daemon] networkBecameReachable — loop already running");
        return;
    }

    [_stateLock lock];
    _consecutiveFailures = 0;
    _shouldDisconnect    = NO;
    [_stateLock unlock];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self connectionLoop];
    });
}

- (void)requestDisconnect {
    [_stateLock lock];
    _shouldDisconnect = YES;
    [_stateLock unlock];
    sendClientDisconnect();
    disconnectFromServer();
}

/* ── Connection loop ────────────────────────────────────────────── */

- (void)connectionLoop {
    [_stateLock lock];
    if (_isRunning) {
        [_stateLock unlock];
        NSLog(@"[FSM] connectionLoop already running — ignoring duplicate call");
        return;
    }
    _isRunning = YES;
    [_stateLock unlock];

    NSLog(@"[FSM] Connection loop started");

    NSString *pubKey = [self getServerPubKey];
    int serverPort   = [serverPortString intValue];

    if (!isValidPort(serverPortString)) {
        NSLog(@"[Daemon] Invalid server port: %@", serverPortString);
        [self transitionToState:SGStateErrorBadConfig];
        goto loop_exit;
    }
    if (!pubKey || [pubKey length] == 0) {
        NSLog(@"[Daemon] Missing server public key");
        [self transitionToState:SGStateErrorBadConfig];
        goto loop_exit;
    }

    {
        const char *ipCStr = [serverIPString UTF8String];

        while (1) {
            @autoreleasepool {

                // ── Stop check ───────────────────────────────────
                [_stateLock lock];
                BOOL stop = _shouldDisconnect;
                [_stateLock unlock];
                if (stop) {
                    NSLog(@"[FSM] Stop requested — exiting loop");
                    break;
                }

                // ── Circuit breaker ──────────────────────────────
                [_stateLock lock];
                int failures = _consecutiveFailures;
                [_stateLock unlock];

                if (failures >= MAX_CONSECUTIVE_FAILURES) {
                    NSLog(@"[FSM] Circuit open after %d failures — waiting %ds",
                          failures, CIRCUIT_OPEN_WAIT_SEC);
                    [self transitionToState:SGStateIdleCircuitOpen
                                 backoffSec:CIRCUIT_OPEN_WAIT_SEC
                                   serverIP:ipCStr];
                    sleep(CIRCUIT_OPEN_WAIT_SEC);
                    [_stateLock lock];
                    _consecutiveFailures = 0;
                    [_stateLock unlock];
                    continue;
                }

                // ── Backoff for this attempt ─────────────────────
                int backoff = INITIAL_BACKOFF_SEC;
                for (int i = 0; i < failures && backoff < MAX_BACKOFF_SEC; i++) {
                    backoff = MIN(backoff * 2, MAX_BACKOFF_SEC);
                }
                int jitter = (int)(arc4random_uniform(MAX_JITTER_SEC + 1));

                // ── Connect ──────────────────────────────────────
                [self transitionToState:SGStateConnecting
                             backoffSec:0
                               serverIP:ipCStr];

                setNotificationDelegate(self);
                int cr = connectToServer(ipCStr, serverPort, pubKey);

                if (cr != 0) {
                    [_stateLock lock];
                    _consecutiveFailures++;
                    failures = _consecutiveFailures;
                    [_stateLock unlock];

                    int delay = MIN(backoff + jitter, MAX_BACKOFF_SEC);
                    NSLog(@"[FSM] Connect failed (%d), retry in %ds (attempt %d)",
                          cr, delay, failures);
                    [self transitionToState:SGStateBackingOff
                                 backoffSec:(uint32_t)delay
                                   serverIP:ipCStr];
                    sleep(delay);
                    continue;
                }

                // ── TCP+TLS up ───────────────────────────────────
                [self transitionToState:SGStateAuthenticating];

                // ── Message loop ─────────────────────────────────
                while (1) {
                    @autoreleasepool {
                        [_stateLock lock];
                        BOOL stopInner = _shouldDisconnect;
                        [_stateLock unlock];
                        if (stopInner) break;

                        int result = handleMessage();
                        if (result == 0) continue;

                        if (result == 4) {
                            NSLog(@"[FSM] Authentication failure — stopping loop");
                            [self transitionToState:SGStateErrorAuth];
                            [_stateLock lock];
                            _shouldDisconnect = YES;
                            [_stateLock unlock];
                        } else {
                            NSLog(@"[FSM] Disconnected (code %d)", result);
                        }
                        break;
                    }
                }

                // ── Connection ended ─────────────────────────────
                sendClientDisconnect();
                disconnectFromServer();

                [_stateLock lock];
                BOOL hardStop = _shouldDisconnect;
                [_stateLock unlock];
                if (hardStop) break;

                [_stateLock lock];
                _consecutiveFailures++;
                failures = _consecutiveFailures;
                [_stateLock unlock];

                int delay = MIN(backoff + jitter, MAX_BACKOFF_SEC);
                NSLog(@"[FSM] Reconnect in %ds (consecutive failures: %d)",
                      delay, failures);
                [self transitionToState:SGStateBackingOff
                             backoffSec:(uint32_t)delay
                               serverIP:ipCStr];
                sleep(delay);

            } // @autoreleasepool
        } // while(1)
    }

loop_exit:
    [_stateLock lock];
    _isRunning = NO;
    [_stateLock unlock];

    NSLog(@"[FSM] Connection loop exited");
    dispatch_semaphore_signal(_loopExitSema);
}

/* ── Credential helpers ─────────────────────────────────────────── */

- (NSString *)getClientAddress {
    NSDictionary *profile = [NSDictionary dictionaryWithContentsOfFile:
        @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist"];
    return profile[@"device_address"];
}

- (NSString *)getServerPubKey {
    NSDictionary *profile = [NSDictionary dictionaryWithContentsOfFile:
        @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist"];
    return profile[@"server_pub_key"];
}

@end

/* ─────────────────────────────────────────────────────────────────
 * Config-reload Darwin notification trampoline
 * ───────────────────────────────────────────────────────────────── */

static void configReloadCallback(CFNotificationCenterRef center,
                                  void *observer,
                                  CFStringRef name,
                                  const void *object,
                                  CFDictionaryRef userInfo) {
    (void)center; (void)name; (void)object; (void)userInfo;
    NotificationDaemon *daemon = (__bridge NotificationDaemon *)observer;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            [daemon handleConfigReload];
        }
    });
}

/* ─────────────────────────────────────────────────────────────────
 * Shared startup helper
 *
 * Registers the daemon for config reloads and runs the run loop.
 * Used by the early-exit paths (disabled, unregistered, DNS failed)
 * so they all share identical idle behaviour rather than duplicating
 * CFNotificationCenterAddObserver + CFRunLoopRun inline.
 * ───────────────────────────────────────────────────────────────── */

static void idleUntilConfigReload(NotificationDaemon *daemon) {
    CFNotificationCenterAddObserver(
        CFNotificationCenterGetDarwinNotifyCenter(),
        (__bridge void *)daemon,
        configReloadCallback,
        CFSTR(kDaemonReloadConfig),
        NULL,
        CFNotificationSuspensionBehaviorDeliverImmediately);
    CFRunLoopRun();
    CFNotificationCenterRemoveObserver(
        CFNotificationCenterGetDarwinNotifyCenter(),
        (__bridge void *)daemon,
        CFSTR(kDaemonReloadConfig),
        NULL);
}

/* ─────────────────────────────────────────────────────────────────
 * main()
 * ───────────────────────────────────────────────────────────────── */

int main(void) {
    @autoreleasepool {
        signal(SIGPIPE, SIG_IGN);
        initOpenSSLOnce();

        // ── StatusServer must be first ────────────────────────────
        int64_t startTime = (int64_t)time(NULL);
        if (StatusServer_start(SS_SOCKET_PATH, startTime) != 0) {
            NSLog(@"[Main] StatusServer failed to start — continuing without it");
        }

        NSLog(@"[Main] Skyglow Notification Daemon starting");

        // ── Preferences ──────────────────────────────────────────
        NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
        NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];
        if (!prefs) {
            NSLog(@"[Main] Failed to read preferences");
            StatusServer_post(SGStateError, 0, 0, NULL);
            StatusServer_shutdown();
            return -1;
        }

        NotificationDaemon *daemon = [[NotificationDaemon alloc] init];
        gDaemon = daemon;

        if (![[prefs objectForKey:@"enabled"] boolValue]) {
            NSLog(@"[Main] Daemon disabled — idling");
            StatusServer_post(SGStateDisabled, 0, 0, NULL);
            idleUntilConfigReload(daemon);
            StatusServer_shutdown();
            [daemon release];
            return 0;
        }

        // ── Profile / registration ────────────────────────────────
        NSString *profilePath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
        NSDictionary *profile = [NSDictionary dictionaryWithContentsOfFile:profilePath];
        NSString *serverAddr  = profile[@"server_address"];

        if (![serverAddr isKindOfClass:[NSString class]] || [serverAddr length] == 0) {
            NSLog(@"[Main] Not registered — idling");
            StatusServer_post(SGStateIdleUnregistered, 0, 0, NULL);
            idleUntilConfigReload(daemon);
            StatusServer_shutdown();
            [daemon release];
            return 0;
        }

        if ([serverAddr length] > 253) {
            NSLog(@"[Main] server_address unreasonably long");
            StatusServer_post(SGStateErrorBadConfig, 0, 0, NULL);
            StatusServer_shutdown();
            [daemon release];
            return -1;
        }

        serverAddress = [serverAddr retain];

        // ── Database ──────────────────────────────────────────────
        db = [[DBManager alloc] init];
        if (!db) {
            NSLog(@"[Main] Failed to initialize database");
            StatusServer_post(SGStateError, 0, 0, NULL);
            StatusServer_shutdown();
            [serverAddress release];    serverAddress    = nil;
            [daemon release];
            return -1;
        }

        // ── DNS resolution with retry ─────────────────────────────
        StatusServer_post(SGStateResolvingDNS, 0, 0, NULL);

        NSDictionary *txtRecords = nil;
        for (int attempt = 1; attempt <= DNS_RETRY_COUNT; attempt++) {
            txtRecords = resolveServerLocation(serverAddr);
            if (txtRecords) break;
            if (attempt < DNS_RETRY_COUNT) {
                NSLog(@"[Main] DNS failed (attempt %d/%d), retrying in %ds",
                      attempt, DNS_RETRY_COUNT, DNS_RETRY_DELAY_SEC);
                sleep(DNS_RETRY_DELAY_SEC);
            }
        }

        if (!txtRecords) {
            NSLog(@"[Main] DNS failed after %d attempts — entering IdleDNSFailed",
                  DNS_RETRY_COUNT);
            StatusServer_post(SGStateIdleDNSFailed, 0, 0, NULL);
            idleUntilConfigReload(daemon);
            StatusServer_shutdown();
            [serverAddress release];    serverAddress    = nil;
            [db release];               db               = nil;
            [daemon release];
            return 0;
        }

        NSString *ip   = txtRecords[@"tcp_addr"];
        NSString *port = txtRecords[@"tcp_port"];

        if (!isValidIPAddress(ip)) {
            NSLog(@"[Main] Invalid IP from DNS: %@", ip);
            StatusServer_post(SGStateErrorBadConfig, 0, 0, NULL);
            StatusServer_shutdown();
            [serverAddress release];    serverAddress    = nil;
            [db release];               db               = nil;
            [daemon release];
            return -1;
        }
        if (!isValidPort(port)) {
            NSLog(@"[Main] Invalid port from DNS: %@", port);
            StatusServer_post(SGStateErrorBadConfig, 0, 0, NULL);
            StatusServer_shutdown();
            [serverAddress release];    serverAddress    = nil;
            [db release];               db               = nil;
            [daemon release];
            return -1;
        }

        serverIPString   = [ip retain];
        serverPortString = [port retain];

        NSLog(@"[Main] Server: %@:%@%@", serverIPString, serverPortString,
              [txtRecords[@"cached"] boolValue] ? @" (cached)" : @"");

        // ── Mach token server ─────────────────────────────────────
        MachMsgs *machMsgs = [[MachMsgs alloc] init];
        [machMsgs startMachServer];

        // ── Config reload listener ────────────────────────────────
        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            (__bridge void *)daemon,
            configReloadCallback,
            CFSTR(kDaemonReloadConfig),
            NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately);

        // ── Reachability monitoring ───────────────────────────────
        [daemon startMonitoringNetworkReachability];

        // Allow the reachability ref to fire its initial callback before
        // we query flags synchronously.
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 2.0, false);

        SCNetworkReachabilityFlags flags = [daemon getReachabilityFlags];
        BOOL reachable    = (flags & kSCNetworkFlagsReachable) != 0;
        BOOL needsConn    = (flags & kSCNetworkFlagsConnectionRequired) != 0;
        BOOL reachableNow = reachable && !needsConn;

        if (reachableNow) {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                [daemon connectionLoop];
            });
        } else {
            NSLog(@"[Main] Network not reachable at start — waiting for callback");
            StatusServer_post(SGStateIdleNoNetwork, 0, 0, [ip UTF8String]);
        }

        // ── Run loop ──────────────────────────────────────────────
        CFRunLoopRun();

        // ── Teardown ──────────────────────────────────────────────
        NSLog(@"[Main] Run loop exited — shutting down");
        [daemon requestDisconnect];

        CFNotificationCenterRemoveObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            (__bridge void *)daemon,
            CFSTR(kDaemonReloadConfig),
            NULL);

        StatusServer_shutdown();

        [serverAddress release];    serverAddress    = nil;
        [serverIPString release];   serverIPString   = nil;
        [serverPortString release]; serverPortString = nil;
        [db release];               db               = nil;
        [machMsgs release];
        [daemon release];
        gDaemon = nil;
    }

    NSLog(@"[Main] Skyglow Notification Daemon exited cleanly");
    return 0;
}