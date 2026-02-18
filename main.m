#import "main.h"
#include <objc/NSObjCRuntime.h>
#include <CoreFoundation/CFBase.h>
#include "ServerLocationFinder.h"
#include <Foundation/NSObjCRuntime.h>
#include "openssl/pem.h"
#include "Protocol.h"
#include <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#import "CryptoManager.h"
#import "DBManager.h"
#import "TweakMachMessages.h"
#include <bootstrap.h>
#import "Globals.h"
#include <signal.h>

// How long to trust cached DNS (1 hour)
#define DNS_CACHE_MAX_AGE_SECONDS  3600.0

// ──────────────────────────────────────────────
// Globals
// ──────────────────────────────────────────────

NSString *serverAddress = nil;
DBManager *db           = nil;
char *serverIP          = NULL;
char *serverPortStr     = NULL;

/// The single daemon instance. Set after init in main().
static NotificationDaemon *gDaemon = nil;

/// OpenSSL initialized flag — call SSL_library_init() exactly once.
static BOOL gSSLInitialized = NO;

// ──────────────────────────────────────────────
// OpenSSL one-time init
// ──────────────────────────────────────────────

static void ensureSSLInitialized(void) {
    if (!gSSLInitialized) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        gSSLInitialized = YES;
    }
}

// ──────────────────────────────────────────────
// Backoff helpers
// ──────────────────────────────────────────────

/// Compute the next backoff interval with jitter.
/// Progression: INITIAL, INITIAL*2, INITIAL*4, ..., capped at MAX_BACKOFF_SEC.
/// Adds uniform random jitter of [0, MAX_JITTER_SEC] to prevent thundering herd.
static int computeBackoff(int currentBackoff) {
    int next = MIN(currentBackoff * 2, MAX_BACKOFF_SEC);
    // Add jitter (arc4random_uniform is available on iOS 6+)
    int jitter = (int)arc4random_uniform(MAX_JITTER_SEC + 1);
    return next + jitter;
}

/// Sleep in 1-second increments, checking _shouldDisconnect each second.
/// Returns YES if sleep completed, NO if interrupted by disconnect.
static BOOL interruptibleSleep(NotificationDaemon *daemon, int seconds) {
    for (int i = 0; i < seconds; i++) {
        sleep(1);
        @synchronized(daemon) {
            if (daemon->_shouldDisconnect) return NO;
        }
    }
    return YES;
}

// ──────────────────────────────────────────────
// SendPush — forward a notification via Mach IPC
// ──────────────────────────────────────────────

static kern_return_t SendPush(NSString *topic, NSDictionary *userInfo) {
    if (!topic || [topic length] == 0) {
        NSLog(@"[SendPush] Missing topic");
        return KERN_INVALID_ARGUMENT;
    }

    NSData *topicData = [topic dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
    if (!topicData || topicData.length == 0) {
        NSLog(@"[SendPush] Topic UTF8 conversion failed");
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
        mach_port_deallocate(mach_task_self(), servicePort);
        return KERN_RESOURCE_SHORTAGE;
    }

    MachPushRequestMessage msg;
    memset(&msg, 0, sizeof(msg));

    msg.header.msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_remote_port = servicePort;
    msg.header.msgh_id          = SKYGLOW_REQUEST_PUSH;
    msg.body.msgh_descriptor_count = 0;
    msg.type = SKYGLOW_REQUEST_PUSH;

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
        mach_port_deallocate(mach_task_self(), servicePort);
        return KERN_INVALID_ARGUMENT;
    }
    msg.header.msgh_size = (mach_msg_size_t)usedSize;

    kr = mach_msg(&msg.header, MACH_SEND_MSG, msg.header.msgh_size, 0,
                  MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[SendPush] mach_msg failed: %s (%d)", mach_error_string(kr), kr);
    }

    mach_port_deallocate(mach_task_self(), servicePort);
    return kr;
}

// ──────────────────────────────────────────────
// DNS resolution with caching
// ──────────────────────────────────────────────

/// Resolve server IP and port, using cache first, then live DNS.
/// Returns a dictionary with @"tcp_addr" and @"tcp_port", or nil on failure.
static NSDictionary *resolveServerLocation(NSString *serverAddr) {
    NSString *dnsName = [@"_sgn." stringByAppendingString:serverAddr];

    // 1. Try cache first
    NSDictionary *cached = [db cachedDNSForDomain:dnsName maxAgeSeconds:DNS_CACHE_MAX_AGE_SECONDS];
    if (cached) {
        NSLog(@"[Main] Using cached DNS for %@ (age: %.0f s)", dnsName, [cached[@"age"] doubleValue]);
        return cached;
    }

    // 2. Live DNS lookup
    NSLog(@"[Main] Cache miss — performing live DNS lookup for %@", dnsName);
    NSDictionary *txtRecords = QueryServerLocation(dnsName);
    if (!txtRecords) return nil;

    NSString *ip   = txtRecords[@"tcp_addr"];
    NSString *port = txtRecords[@"tcp_port"];

    // 3. Cache the result
    if (ip && port) {
        [db storeDNSCache:dnsName ip:ip port:port];
        NSLog(@"[Main] Cached DNS: %@ -> %@:%@", dnsName, ip, port);
    }

    return txtRecords;
}

/// Refresh DNS cache in the background (non-blocking).
/// Called after each successful connection to keep cache fresh.
static void refreshDNSCacheAsync(NSString *serverAddr) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
        NSString *dnsName = [@"_sgn." stringByAppendingString:serverAddr];
        NSDictionary *txtRecords = QueryServerLocation(dnsName);
        if (txtRecords) {
            NSString *ip   = txtRecords[@"tcp_addr"];
            NSString *port = txtRecords[@"tcp_port"];
            if (ip && port) {
                [db storeDNSCache:dnsName ip:ip port:port];
                NSLog(@"[Main] DNS cache refreshed: %@:%@", ip, port);
            }
        }
    });
}

// ──────────────────────────────────────────────
// Config reading helpers
// ──────────────────────────────────────────────

/// Re-read the main prefs and return whether daemon is enabled.
static BOOL readEnabledState(void) {
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:
                           @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist"];
    return [[prefs objectForKey:@"enabled"] boolValue];
}

/// Re-read the profile plist. Returns nil if not registered.
static NSDictionary *readProfile(void) {
    NSDictionary *profile = [NSDictionary dictionaryWithContentsOfFile:
                             @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist"];
    NSString *addr = profile[@"server_address"];
    if (!addr || ![addr isKindOfClass:[NSString class]] || [addr length] == 0) return nil;
    return profile;
}

// ──────────────────────────────────────────────
// Validation
// ──────────────────────────────────────────────

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

// ──────────────────────────────────────────────
// Status publishing
// ──────────────────────────────────────────────

void updateStatus(NSString *status) {
    NSDictionary *dict = @{
        @"lastUpdated":   [NSDate date],
        @"currentStatus": status
    };
    [dict writeToFile:@"/var/mobile/Library/Preferences/com.skyglow.sndp.status.plist" atomically:YES];
    CFNotificationCenterPostNotificationWithOptions(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFSTR(kDaemonStatusNewStatus),
        NULL, NULL,
        kCFNotificationDeliverImmediately);
}

// ──────────────────────────────────────────────
// NotificationDaemon
// ──────────────────────────────────────────────

@implementation NotificationDaemon

- (id)init {
    if ((self = [super init])) {
        _isRunning = NO;
        _shouldDisconnect = NO;
        _authFailed = NO;
        _networkWasLost = NO;
        _consecutiveFailures = 0;
    }
    return self;
}

- (void)requestDisconnect {
    @synchronized(self) {
        _shouldDisconnect = YES;
    }
    // Force the SSL read to unblock by shutting down the socket.
    // disconnectFromServer() is thread-safe and handles the cleanup.
    disconnectFromServer();
}

- (void)networkBecameReachable {
    NSLog(@"[Daemon] Network became reachable — resetting failure counters");

    @synchronized(self) {
        _consecutiveFailures = 0;
        _networkWasLost = NO;

        // Don't retry if auth explicitly failed — needs config reload
        if (_authFailed) {
            NSLog(@"[Daemon] Auth previously failed — waiting for config reload, not reconnecting");
            return;
        }

        // If already running, the loop will handle itself
        if (_isRunning) {
            NSLog(@"[Daemon] Connection loop already running");
            return;
        }
    }

    // Only attempt connection if we have a server configured
    if (serverAddress && serverIP && serverPortStr) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [self exponentialBackoffConnect];
        });
    } else {
        NSLog(@"[Daemon] Network reachable but no server configured");
    }
}

/// Re-reads config and adjusts daemon state.
/// Called on background thread when kDaemonReloadConfig fires.
- (void)handleConfigReload {
    NSLog(@"[Daemon] Config reload requested");

    // 1. Check if daemon is enabled
    if (!readEnabledState()) {
        NSLog(@"[Daemon] Config reload: daemon disabled, disconnecting");
        [self requestDisconnect];
        updateStatus(kStatusDisabled);
        return;
    }

    // 2. Check if still registered
    NSDictionary *profile = readProfile();
    if (!profile) {
        NSLog(@"[Daemon] Config reload: not registered, disconnecting");
        [self requestDisconnect];
        updateStatus(kStatusEnabledNotRegistered);
        return;
    }

    // 3. Clear auth failure flag — user may have re-registered with new credentials
    @synchronized(self) {
        _authFailed = NO;
        _consecutiveFailures = 0;
    }

    // 4. We're enabled and registered. If not already running, resolve and connect.
    NSString *newServerAddr = profile[@"server_address"];
    NSLog(@"[Daemon] Config reload: enabled and registered (server=%@)", newServerAddr);

    // Update globals if server address changed or wasn't set
    if (!serverAddress || ![serverAddress isEqualToString:newServerAddr]) {
        NSLog(@"[Daemon] Config reload: server address changed/set, updating");

        // Disconnect current connection if any
        [self requestDisconnect];

        // Update server address
        [serverAddress release];
        serverAddress = [newServerAddr retain];

        // Initialize DB if not already done (for fresh registrations)
        if (!db) {
            db = [[DBManager alloc] init];
            if (!db) {
                NSLog(@"[Daemon] Failed to init database");
                updateStatus(kStatusError);
                return;
            }
        }

        // Resolve DNS
        NSDictionary *txtRecords = resolveServerLocation(newServerAddr);
        if (!txtRecords) {
            NSLog(@"[Daemon] Config reload: DNS resolution failed");
            updateStatus(kStatusEnabledNotConnected);
            return;
        }

        NSString *ip   = txtRecords[@"tcp_addr"];
        NSString *port = txtRecords[@"tcp_port"];

        if (!isValidIPAddress(ip) || !isValidPort(port)) {
            NSLog(@"[Daemon] Config reload: invalid server config (ip=%@ port=%@)", ip, port);
            updateStatus(kStatusServerConfigBad);
            return;
        }

        // Update global IP/port
        if (serverIP)      { free(serverIP);      serverIP = NULL; }
        if (serverPortStr) { free(serverPortStr);  serverPortStr = NULL; }
        serverIP      = strdup([ip UTF8String]);
        serverPortStr = strdup([port UTF8String]);

        NSLog(@"[Daemon] Config reload: resolved to %s:%s", serverIP, serverPortStr);
    }

    // 5. Start connecting if not already running
    @synchronized(self) {
        if (_isRunning) {
            NSLog(@"[Daemon] Config reload: connection loop already running");
            return;
        }
    }

    updateStatus(kStatusEnabledNotConnected);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self exponentialBackoffConnect];
    });
}

- (void)processNotificationMessage:(NSDictionary *)messageDict {
    NSData *routingKey = messageDict[@"routing_key"];
    if (!routingKey) {
        NSLog(@"[Daemon] Notification missing routing_key");
        return;
    }

    NSDictionary *routingData = [db dataForRoutingKey:routingKey];
    if (!routingData) {
        NSLog(@"[Daemon] No routing data for key");
        return;
    }

    NSString *bundleID  = routingData[@"bundleID"];
    NSString *messageID = messageDict[@"message_id"];
    if (!messageID) {
        NSLog(@"[Daemon] Notification missing message_id");
        return;
    }

    NSDictionary *userInfo = nil;

    if ([messageDict[@"is_encrypted"] boolValue]) {
        NSString *outputType = messageDict[@"data_type"];
        NSData *ciphertext   = messageDict[@"ciphertext"];
        NSData *iv           = messageDict[@"iv"];

        if (!ciphertext || !iv) {
            NSLog(@"[Daemon] Encrypted notification missing ciphertext/iv");
            ackNotification(messageID, 1);
            return;
        }

        NSData *decrypted = decryptAESGCM(ciphertext, routingData[@"e2eeKey"], iv, nil);
        if (!decrypted) {
            NSLog(@"[Daemon] Decryption failed");
            ackNotification(messageID, 1);
            return;
        }

        NSError *error = nil;
        if ([outputType isEqualToString:@"json"]) {
            userInfo = [NSJSONSerialization JSONObjectWithData:decrypted options:0 error:&error];
        } else if ([outputType isEqualToString:@"plist"]) {
            userInfo = [NSPropertyListSerialization propertyListWithData:decrypted
                                                                options:NSPropertyListImmutable
                                                                 format:nil
                                                                  error:&error];
        } else {
            NSLog(@"[Daemon] Unknown data_type: %@", outputType);
            ackNotification(messageID, 2);
            return;
        }

        if (!userInfo) {
            NSLog(@"[Daemon] Deserialization failed: %@", error);
            ackNotification(messageID, 2);
            return;
        }
    } else {
        userInfo = messageDict[@"data"];
    }

    SendPush(bundleID, userInfo);
    ackNotification(messageID, 0);
}

- (void)handleWelcomeMessage {
    NSString *clientAddress = [self getClientAddress];
    RSA *privKey = getClientPrivKey();
    NSString *language = [[NSLocale preferredLanguages] firstObject];

    if (!clientAddress || !privKey) {
        NSLog(@"[Daemon] Missing credentials for login");
        return;
    }
    startLogin(clientAddress, privKey, language);
}

- (void)authenticationSuccessful {
    updateStatus(kStatusConnected);

    // Opportunistically refresh DNS cache in the background
    if (serverAddress) {
        refreshDNSCacheAsync(serverAddress);
    }
}

// ──────────────────────────────────────────────
// Connection loop
//
// Reconnection strategy (modeled after APNS behavior):
//
//   1. On connection failure: exponential backoff with jitter.
//      Progression: 2s → 4s → 8s → 16s → 32s → 60s → 120s → 300s → 600s (cap).
//
//   2. After MAX_CONSECUTIVE_FAILURES (12) failures, the loop
//      exits and the daemon goes idle. It will only reconnect
//      when the network state changes (reachability callback)
//      or when the user triggers a config reload from settings.
//
//   3. Authentication failure immediately stops the loop and
//      sets _authFailed. The daemon won't retry until the user
//      re-registers or changes config (which posts kDaemonReloadConfig).
//
//   4. Successful message receipt resets the backoff to initial.
//
//   5. Network loss (detected by reachability callback) exits
//      the loop. Network regain resets all counters and restarts.
// ──────────────────────────────────────────────

- (void)exponentialBackoffConnect {
    @synchronized(self) {
        if (_isRunning) {
            NSLog(@"[Daemon] Connection loop already running");
            return;
        }
        _isRunning = YES;
        _shouldDisconnect = NO;
    }

    NSLog(@"[Daemon] Starting connection loop");
    int backoff = INITIAL_BACKOFF_SEC;
    NSString *serverPubKey = [self getServerPubKey];
    int serverPort = atoi(serverPortStr);

    if (serverPort <= 0) {
        NSLog(@"[Daemon] Invalid server port");
        updateStatus(kStatusServerConfigBad);
        @synchronized(self) { _isRunning = NO; }
        return;
    }

    if (!serverPubKey || [serverPubKey length] == 0) {
        NSLog(@"[Daemon] Missing server public key");
        updateStatus(kStatusServerConfigBad);
        @synchronized(self) { _isRunning = NO; }
        return;
    }

    updateStatus(kStatusEnabledNotConnected);

    while (1) {
        // ── Check if we've been asked to stop ──
        @synchronized(self) {
            if (_shouldDisconnect) {
                NSLog(@"[Daemon] Disconnect requested, exiting connection loop");
                break;
            }
        }

        // ── Check if we've exhausted retries ──
        @synchronized(self) {
            if (_consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
                NSLog(@"[Daemon] %d consecutive failures — going idle. "
                      @"Will retry on network change or config reload.",
                      _consecutiveFailures);
                break;
            }
        }

        setNotificationDelegate(self);

        int cr = connectToServer(serverIP, serverPort, serverPubKey);
        if (cr != 0) {
            // Check before sleeping — disconnect may have been requested
            @synchronized(self) {
                if (_shouldDisconnect) {
                    NSLog(@"[Daemon] Disconnect requested after failed connect");
                    break;
                }
                _consecutiveFailures++;
            }

            int failures;
            @synchronized(self) { failures = _consecutiveFailures; }

            NSLog(@"[Daemon] Connection failed (%d), attempt %d/%d, retrying in %d s",
                  cr, failures, MAX_CONSECUTIVE_FAILURES, backoff);
            updateStatus(kStatusEnabledNotConnected);

            if (!interruptibleSleep(self, backoff)) break;
            backoff = computeBackoff(backoff);
            continue;
        }

        // ── Connected — reset failure counter ──
        @synchronized(self) {
            _consecutiveFailures = 0;
        }
        backoff = INITIAL_BACKOFF_SEC;

        updateStatus(kStatusConnectedNotAuthenticated);
        NSLog(@"[Daemon] Connected to %s:%d", serverIP, serverPort);

        // ── Message loop ──
        BOOL authFailure = NO;
        while (1) {
            int result = handleMessage();
            if (result == 0) {
                continue;
            }
            if (result == 4) {
                NSLog(@"[Daemon] Auth failure (code %d) — will not retry automatically", result);
                updateStatus(kStatusErrorInAuth);
                authFailure = YES;
            } else {
                NSLog(@"[Daemon] Disconnected (code %d)", result);
            }
            break;
        }

        disconnectFromServer();

        // ── Auth failure: stop retrying until config reload ──
        if (authFailure) {
            @synchronized(self) {
                _authFailed = YES;
            }
            NSLog(@"[Daemon] Auth failed — going idle until config reload");
            break;
        }

        // If disconnect was requested externally, don't reconnect
        @synchronized(self) {
            if (_shouldDisconnect) {
                NSLog(@"[Daemon] Disconnect requested, exiting connection loop");
                break;
            }
        }

        updateStatus(kStatusEnabledNotConnected);

        NSLog(@"[Daemon] Reconnecting in %d s", backoff);
        if (!interruptibleSleep(self, backoff)) break;
        backoff = computeBackoff(backoff);
    }

    @synchronized(self) { _isRunning = NO; }
    NSLog(@"[Daemon] Connection loop exited");

    // If we exhausted retries (not auth fail, not user disconnect),
    // schedule a slow-poll retry in 30 minutes. This handles the case
    // where the server was temporarily down but network stayed up, so
    // no reachability change fires to restart us.
    BOOL shouldSlowPoll = NO;
    @synchronized(self) {
        shouldSlowPoll = !_authFailed && !_shouldDisconnect
                         && _consecutiveFailures >= MAX_CONSECUTIVE_FAILURES;
    }
    if (shouldSlowPoll) {
        NSLog(@"[Daemon] Scheduling slow-poll retry in 30 minutes");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1800 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            @synchronized(self) {
                _consecutiveFailures = 0;
            }
            [self exponentialBackoffConnect];
        });
    }
}

- (void)dealloc {
    if (_reachabilityRef != NULL) {
        SCNetworkReachabilitySetCallback(_reachabilityRef, NULL, NULL);
        SCNetworkReachabilitySetDispatchQueue(_reachabilityRef, NULL);
        CFRelease(_reachabilityRef);
        _reachabilityRef = NULL;
    }
    [super dealloc];
}

- (void)startMonitoringNetworkReachability {
    struct sockaddr_in zeroAddress;
    memset(&zeroAddress, 0, sizeof(zeroAddress));
    zeroAddress.sin_len    = sizeof(zeroAddress);
    zeroAddress.sin_family = AF_INET;

    _reachabilityRef = SCNetworkReachabilityCreateWithAddress(NULL, (const struct sockaddr *)&zeroAddress);
    if (!_reachabilityRef) {
        NSLog(@"[Daemon] Failed to create reachability ref");
        return;
    }

    SCNetworkReachabilityContext context = {0, (__bridge void *)(self), NULL, NULL, NULL};

    if (!SCNetworkReachabilitySetCallback(_reachabilityRef, ReachabilityCallback, &context)) {
        NSLog(@"[Daemon] Could not set reachability callback");
        return;
    }

    dispatch_queue_t bgQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    if (!SCNetworkReachabilitySetDispatchQueue(_reachabilityRef, bgQueue)) {
        NSLog(@"[Daemon] Could not set reachability queue");
    } else {
        NSLog(@"[Daemon] Reachability monitoring started");
    }
}

- (SCNetworkReachabilityFlags)getReachabilityFlags {
    SCNetworkReachabilityFlags flags = 0;
    if (_reachabilityRef) SCNetworkReachabilityGetFlags(_reachabilityRef, &flags);
    return flags;
}

- (NSString *)getClientAddress {
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    return prefs[@"device_address"];
}

- (NSString *)getServerPubKey {
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    return prefs[@"server_pub_key"];
}

// NOTE: deviceTokenRegistrationCompleted: removed — tokens are now generated locally
// with no server round-trip. See Tokens.m for the new flow.

@end

// ──────────────────────────────────────────────
// Reachability callback
// ──────────────────────────────────────────────

static void ReachabilityCallback(SCNetworkReachabilityRef target,
                                 SCNetworkReachabilityFlags flags,
                                 void *info) {
    BOOL reachable    = (flags & kSCNetworkFlagsReachable) != 0;
    BOOL needsConn    = (flags & kSCNetworkFlagsConnectionRequired) != 0;
    BOOL reachableNow = reachable && !needsConn;

    NotificationDaemon *daemon = (__bridge NotificationDaemon *)info;

    if (reachableNow) {
        NSLog(@"[Reachability] Network reachable");
        [daemon networkBecameReachable];
    } else {
        NSLog(@"[Reachability] Network unreachable");
        @synchronized(daemon) {
            daemon->_networkWasLost = YES;
        }
        // If we have a server configured, update status
        if (serverAddress) {
            updateStatus(kStatusEnabledNotConnected);
        }
    }
}

// ──────────────────────────────────────────────
// Darwin notification callback (kDaemonReloadConfig)
// ──────────────────────────────────────────────

static void ConfigReloadCallback(CFNotificationCenterRef center,
                                 void *observer,
                                 CFStringRef name,
                                 const void *object,
                                 CFDictionaryRef userInfo) {
    NotificationDaemon *daemon = (__bridge NotificationDaemon *)observer;
    // Dispatch to background to avoid blocking the notification center
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [daemon handleConfigReload];
    });
}

// ──────────────────────────────────────────────
// main
// ──────────────────────────────────────────────

int main(void) {
    @autoreleasepool {
        signal(SIGPIPE, SIG_IGN);

        NSLog(@"Speedy Execution Is The Mother Of Good Fortune");

        // ── Initialize OpenSSL once ──
        ensureSSLInitialized();

        // ── Read preferences ──
        NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
        NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];
        if (!prefs) {
            // First launch — create default prefs with enabled=YES
            NSLog(@"[Main] No preferences found, creating defaults");
            NSDictionary *defaults = @{@"enabled": @YES};
            [defaults writeToFile:plistPath atomically:YES];
            prefs = defaults;
        }

        if (![[prefs objectForKey:@"enabled"] boolValue]) {
            NSLog(@"[Main] Daemon disabled");
            updateStatus(kStatusDisabled);
            return 0;
        }

        // ── Initialize database (needed for DNS cache and tokens) ──
        db = [[DBManager alloc] init];
        if (!db) {
            NSLog(@"[Main] Failed to init database");
            updateStatus(kStatusError);
            return -1;
        }

        // ── Start Mach server (always — even if not registered, so tweak can request tokens later) ──
        MachMsgs *machMsgs = [[MachMsgs alloc] init];
        [machMsgs startMachServer];

        // ── Start network monitoring ──
        NotificationDaemon *daemon = [[NotificationDaemon alloc] init];
        gDaemon = daemon;
        [daemon startMonitoringNetworkReachability];

        // ── Listen for config reload notifications from settings ──
        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            (__bridge const void *)daemon,
            ConfigReloadCallback,
            CFSTR(kDaemonReloadConfig),
            NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately);

        // ── Read profile ──
        NSString *profilePath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
        NSDictionary *profile = [NSDictionary dictionaryWithContentsOfFile:profilePath];

        NSString *serverAddr = profile[@"server_address"];
        if (![serverAddr isKindOfClass:[NSString class]] || [serverAddr length] == 0) {
            NSLog(@"[Main] Not registered. Idling — waiting for registration via config reload.");
            updateStatus(kStatusEnabledNotRegistered);
            CFRunLoopRun();
            return 0;
        }

        if ([serverAddr length] > 16) {
            NSLog(@"[Main] server_address exceeds 16 chars");
            updateStatus(kStatusServerConfigBad);
            return -1;
        }
        serverAddress = [serverAddr retain];

        // ── Resolve server location (cache → DNS fallback) ──
        NSDictionary *txtRecords = resolveServerLocation(serverAddr);
        if (!txtRecords) {
            NSLog(@"[Main] Failed to resolve server location");
            updateStatus(kStatusEnabledNotConnected);
            // Don't exit — stay alive so config reload or reachability can retry later
            CFRunLoopRun();
            return 0;
        }

        NSString *ip   = txtRecords[@"tcp_addr"];
        NSString *port = txtRecords[@"tcp_port"];

        if (!isValidIPAddress(ip)) {
            NSLog(@"[Main] Invalid IP: %@", ip);
            updateStatus(kStatusServerConfigBad);
            return -1;
        }
        if (!isValidPort(port)) {
            NSLog(@"[Main] Invalid port: %@", port);
            updateStatus(kStatusServerConfigBad);
            return -1;
        }

        serverIP      = strdup([ip UTF8String]);
        serverPortStr = strdup([port UTF8String]);
        NSLog(@"[Main] Server: %s:%s%@", serverIP, serverPortStr,
              [txtRecords[@"cached"] boolValue] ? @" (from cache)" : @"");

        updateStatus(kStatusEnabledNotConnected);

        // ── Kick off initial connection on a background thread ──
        // The main thread enters CFRunLoopRun() immediately so it can
        // always service reachability and config-reload callbacks.
        SCNetworkReachabilityFlags flags = [daemon getReachabilityFlags];
        BOOL reachable    = (flags & kSCNetworkFlagsReachable) != 0;
        BOOL needsConn    = (flags & kSCNetworkFlagsConnectionRequired) != 0;
        BOOL reachableNow = reachable && !needsConn;

        if (reachableNow) {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                [daemon exponentialBackoffConnect];
            });
        } else {
            NSLog(@"[Main] Network not reachable — waiting for callback");
            updateStatus(kStatusEnabledNotConnected);
        }

        // Keep the process alive. Reachability and config reload callbacks
        // will restart the connection loop on background threads as needed.
        CFRunLoopRun();

        if (serverIP)      { free(serverIP);      serverIP = NULL; }
        if (serverPortStr) { free(serverPortStr);  serverPortStr = NULL; }
    }
    NSLog(@"Skyglow Notifications Daemon exited");
    return 0;
}