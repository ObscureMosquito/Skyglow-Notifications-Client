#ifndef SKYGLOW_MAIN_H
#define SKYGLOW_MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import "Protocol.h"
#import "AppMachMsgs.h"

// ──────────────────────────────────────────────
// Reconnection tuning
// ──────────────────────────────────────────────

/// Initial backoff delay in seconds after a failed connection.
#define INITIAL_BACKOFF_SEC         2

/// Maximum backoff delay in seconds (10 minutes).
#define MAX_BACKOFF_SEC             600

/// Maximum consecutive failures before the connection loop
/// goes idle and waits for a reachability change or config reload.
/// At backoff progression 2,4,8,16,32,60,120,300,600,600,...
/// 12 attempts ≈ ~30 minutes of trying before going idle.
#define MAX_CONSECUTIVE_FAILURES    12

/// Maximum jitter added to backoff (seconds).
/// Prevents thundering-herd when the server restarts and
/// all devices try to reconnect at the exact same moment.
#define MAX_JITTER_SEC              5

// ──────────────────────────────────────────────
// Darwin Notifications
// ──────────────────────────────────────────────

/// Posted by daemon when status changes; settings UI listens to refresh.
#define kDaemonStatusNewStatus   "com.skyglow.snd.request_update"

/// Posted by settings when config changes (register, unregister, enable/disable).
/// Daemon listens and responds by re-reading config and adjusting state.
#define kDaemonReloadConfig      "com.skyglow.snd.reload_config"

// ──────────────────────────────────────────────
// Status strings (written to status plist, read by UI)
// ──────────────────────────────────────────────

#define kStatusDisabled                    @"Disabled"
#define kStatusEnabledNotRegistered        @"EnabledNotRegistered"
#define kStatusEnabledNotConnected         @"EnabledNotConnected"
#define kStatusConnectedNotAuthenticated   @"ConnectedNotAuthenticated"
#define kStatusConnected                   @"Connected"
#define kStatusConnectionClosed            @"ConnectionClosed"
#define kStatusError                       @"Error"
#define kStatusErrorInAuth                 @"ErrorInAuth"
#define kStatusServerConfigBad             @"ServerConfigBad"

void updateStatus(NSString *status);
static void ReachabilityCallback(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags flags, void *info);

@interface NotificationDaemon : NSObject <NotificationDelegate> {
@public
    SCNetworkReachabilityRef _reachabilityRef;
    BOOL _isRunning;
    BOOL _shouldDisconnect;
    BOOL _authFailed;
    BOOL _networkWasLost;
    int  _consecutiveFailures;
}

- (void)startMonitoringNetworkReachability;
- (void)exponentialBackoffConnect;

/// Called when network transitions to reachable.
/// Resets failure counters and restarts the connection loop.
- (void)networkBecameReachable;

/// Called when settings posts kDaemonReloadConfig.
/// Re-reads prefs/profile and adjusts connection state accordingly.
- (void)handleConfigReload;

/// Request the connection loop to stop. Thread-safe.
- (void)requestDisconnect;

@end

#endif /* SKYGLOW_MAIN_H */