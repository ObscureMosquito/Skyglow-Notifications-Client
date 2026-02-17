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
// NotificationDaemon
// ──────────────────────────────────────────────

@implementation NotificationDaemon

- (id)init {
    if ((self = [super init])) {
        _disconnectionTimes = [[NSMutableArray alloc] init];
        _isRunning = NO;
    }
    return self;
}

- (void)disableDaemon {
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    if (!prefs) prefs = [NSMutableDictionary dictionary];
    [prefs setObject:@NO forKey:@"enabled"];
    [prefs writeToFile:plistPath atomically:YES];
    updateStatus(kStatusDisabled);
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

- (void)checkForRapidDisconnections {
    NSDate *cutoff = [NSDate dateWithTimeIntervalSinceNow:-10.0];
    NSMutableArray *recent = [NSMutableArray array];

    for (NSDate *t in _disconnectionTimes) {
        if ([t compare:cutoff] == NSOrderedDescending) {
            [recent addObject:t];
        }
    }

    [_disconnectionTimes setArray:recent];

    if ([_disconnectionTimes count] >= 3) {
        NSLog(@"[Daemon] %lu disconnections in 10 s — disabling",
              (unsigned long)[_disconnectionTimes count]);
        [self disableDaemon];
        exit(-3);
    }
}

- (void)exponentialBackoffConnect {
    @synchronized(self) {
        if (_isRunning) {
            NSLog(@"[Daemon] Connection loop already running");
            return;
        }
        _isRunning = YES;
    }

    NSLog(@"[Daemon] Starting connection loop");
    int backoff = 1;
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
        [self checkForRapidDisconnections];

        setNotificationDelegate(self);

        int cr = connectToServer(serverIP, serverPort, serverPubKey);
        if (cr != 0) {
            NSLog(@"[Daemon] Connection failed (%d), retrying in %d s", cr, backoff);
            updateStatus(kStatusEnabledNotConnected);
            sleep(backoff);
            backoff = MIN(backoff * 2, MAX_BACKOFF);
            continue;
        }

        updateStatus(kStatusConnectedNotAuthenticated);
        NSLog(@"[Daemon] Connected to %s:%d", serverIP, serverPort);

        // Message loop
        while (1) {
            int result = handleMessage();
            if (result == 0) {
                backoff = 1;
                continue;
            }
            if (result == 4) {
                NSLog(@"[Daemon] Auth failure (code %d)", result);
                updateStatus(kStatusErrorInAuth);
            } else {
                NSLog(@"[Daemon] Disconnected (code %d)", result);
            }
            break;
        }

        disconnectFromServer();
        [_disconnectionTimes addObject:[NSDate date]];
        updateStatus(kStatusEnabledNotConnected);

        NSLog(@"[Daemon] Reconnecting in %d s", backoff);
        sleep(backoff);
        backoff = MIN(backoff * 2, MAX_BACKOFF);
    }

    @synchronized(self) { _isRunning = NO; }
}

- (void)dealloc {
    if (_reachabilityRef != NULL) {
        SCNetworkReachabilitySetCallback(_reachabilityRef, NULL, NULL);
        SCNetworkReachabilitySetDispatchQueue(_reachabilityRef, NULL);
        CFRelease(_reachabilityRef);
        _reachabilityRef = NULL;
    }
    [_disconnectionTimes release];
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

- (void)deviceTokenRegistrationCompleted:(NSString *)bundleId {
    // Ack handled by semaphore in Protocol.m
}

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
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [daemon exponentialBackoffConnect];
        });
    } else {
        NSLog(@"[Reachability] Network unreachable");
        updateStatus(kStatusEnabledNotConnected);
    }
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
// main
// ──────────────────────────────────────────────

int main(void) {
    @autoreleasepool {
        signal(SIGPIPE, SIG_IGN);

        NSLog(@"Speedy Execution Is The Mother Of Good Fortune");

        // ── Read preferences ──
        NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
        NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];
        if (!prefs) {
            NSLog(@"[Main] Failed to read preferences");
            updateStatus(kStatusError);
            return -1;
        }

        if (![[prefs objectForKey:@"enabled"] boolValue]) {
            NSLog(@"[Main] Daemon disabled");
            updateStatus(kStatusDisabled);
            return 0;
        }

        // ── Read profile ──
        NSString *profilePath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
        NSDictionary *profile = [NSDictionary dictionaryWithContentsOfFile:profilePath];

        NSString *serverAddr = profile[@"server_address"];
        if (![serverAddr isKindOfClass:[NSString class]] || [serverAddr length] == 0) {
            NSLog(@"[Main] Not registered. Idling.");
            updateStatus(kStatusEnabledNotConnected);
            CFRunLoopRun();
            return 0;
        }

        if ([serverAddr length] > 16) {
            NSLog(@"[Main] server_address exceeds 16 chars");
            updateStatus(kStatusServerConfigBad);
            return -1;
        }
        serverAddress = [serverAddr retain];

        // ── Initialize database (needed before DNS cache) ──
        db = [[DBManager alloc] init];
        if (!db) {
            NSLog(@"[Main] Failed to init database");
            updateStatus(kStatusError);
            return -1;
        }

        // ── Resolve server location (cache → DNS fallback) ──
        NSDictionary *txtRecords = resolveServerLocation(serverAddr);
        if (!txtRecords) {
            NSLog(@"[Main] Failed to resolve server location");
            updateStatus(kStatusError);
            return -1;
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

        // ── Start Mach server ──
        MachMsgs *machMsgs = [[MachMsgs alloc] init];
        [machMsgs startMachServer];

        // ── Start network monitoring ──
        NotificationDaemon *daemon = [[NotificationDaemon alloc] init];
        [daemon startMonitoringNetworkReachability];

        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 2, false);

        SCNetworkReachabilityFlags flags = [daemon getReachabilityFlags];
        BOOL reachable    = (flags & kSCNetworkFlagsReachable) != 0;
        BOOL needsConn    = (flags & kSCNetworkFlagsConnectionRequired) != 0;
        BOOL reachableNow = reachable && !needsConn;

        if (reachableNow) {
            [daemon exponentialBackoffConnect];
        } else {
            NSLog(@"[Main] Network not reachable — waiting for callback");
            updateStatus(kStatusEnabledNotConnected);
            CFRunLoopRun();
        }

        if (serverIP)      { free(serverIP);      serverIP = NULL; }
        if (serverPortStr) { free(serverPortStr);  serverPortStr = NULL; }
    }
    NSLog(@"Skyglow Notifications Daemon exited");
    return 0;
}