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
#import <Foundation/Foundation.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import "Protocol.h"
#import "AppMachMsgs.h"
#import "StatusServer.h"

/* ─────────────────────────────────────────────────────────────────
 * Reconnection tuning
 * ───────────────────────────────────────────────────────────────── */

/// Initial backoff delay in seconds after a failed connection.
#define INITIAL_BACKOFF_SEC         2

/// Maximum backoff delay in seconds (10 minutes).
#define MAX_BACKOFF_SEC             600

/// Maximum consecutive failures before the circuit breaker opens.
/// Progression: 2,4,8,16,32,64,128,256,512,600,600,600…
/// ~12 attempts ≈ ~30 minutes of trying before circuit opens.
#define MAX_CONSECUTIVE_FAILURES    12

/// Maximum jitter added to backoff (seconds).
/// Prevents thundering-herd when the server restarts.
#define MAX_JITTER_SEC              5

/// How long the circuit breaker stays open before retrying (seconds).
#define CIRCUIT_OPEN_WAIT_SEC       300

/// DNS resolution retry count on startup failure.
#define DNS_RETRY_COUNT             3

/// Delay between DNS retries on startup (seconds).
#define DNS_RETRY_DELAY_SEC         10

/* ─────────────────────────────────────────────────────────────────
 * Darwin notification names
 *
 * INBOUND (daemon listens):
 *   kDaemonReloadConfig — posted by settings UI on any config change.
 *
 * The daemon does NOT post Darwin notifications outbound.
 * All status is published through StatusServer (Unix domain socket).
 *
 * OUTBOUND (UI → UI only):
 *   "com.skyglow.snd.request_update" — posted between UI processes
 *   to trigger a UI refresh. The daemon never posts this.
 * ───────────────────────────────────────────────────────────────── */

/// Posted by the settings UI when config changes (register, unregister,
/// enable/disable). The daemon responds by calling handleConfigReload.
#define kDaemonReloadConfig     "com.skyglow.snd.reload_config"

/* ─────────────────────────────────────────────────────────────────
 * NotificationDaemon
 *
 * Owns the connection lifecycle. All state transitions must go through
 * transitionToState: which is the sole call site for StatusServer_post().
 *
 * All ivars are private (defined in the @implementation extension in
 * main.m). Callers use only the methods declared below.
 * ───────────────────────────────────────────────────────────────── */

@interface NotificationDaemon : NSObject <NotificationDelegate>

/// Start monitoring network reachability via SCNetworkReachability.
/// Called once from main() after StatusServer_start().
- (void)startMonitoringNetworkReachability;

/// Returns the current SCNetworkReachabilityFlags synchronously.
/// Used on startup to decide whether to connect immediately or wait.
- (SCNetworkReachabilityFlags)getReachabilityFlags;

/// Entry point for the connection loop. Implements exponential backoff
/// with jitter and a circuit breaker.
/// Must be called on a background thread; blocks until stop is requested
/// or an unrecoverable error occurs.
- (void)connectionLoop;

/// Called by the reachability callback when the network becomes reachable.
/// Resets the failure counter and (re)starts the connection loop if not
/// already running. Thread-safe.
- (void)networkBecameReachable;

/// Called when the settings UI posts kDaemonReloadConfig.
/// Re-reads prefs and profile; adjusts connection state accordingly.
/// Thread-safe.
- (void)handleConfigReload;

/// Request the connection loop to stop at its next safe checkpoint.
/// Thread-safe. Does not block.
- (void)requestDisconnect;

/// Transition to a new FSM state. Validates against kLegalTransitions[]
/// and logs a fault on illegal moves without crashing.
/// This is the sole call site for StatusServer_post(). Thread-safe.
- (void)transitionToState:(SGState)newState;

/// Variant that also carries backoff delay and server IP for the payload.
- (void)transitionToState:(SGState)newState
               backoffSec:(uint32_t)backoffSec
                 serverIP:(const char *)serverIP;

@end

#endif /* SKYGLOW_MAIN_H */