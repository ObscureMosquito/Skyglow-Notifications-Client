#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

// Pull in SGState, SGStatusPayload, SS_SOCKET_PATH from the daemon's header.
// The settings bundle links against StatusServer.c (or the .o), so the C
// symbols are available at link time. The header is shared via a relative
// path from the bundle source tree.
#include "../StatusServer.h"

/// Centralized data access for the Skyglow Notifications settings bundle.
/// All plist reading, plist writing, and SQLite queries go through this singleton.
@interface SNDataManager : NSObject

+ (SNDataManager *)shared;

// ── Paths ──
@property (nonatomic, readonly) NSString *mainPrefsPath;
@property (nonatomic, readonly) NSString *profilePath;
@property (nonatomic, readonly) NSString *dbPath;

// ──────────────────────────────────────────────
// Main preferences  (com.skyglow.sndp.plist)
// ──────────────────────────────────────────────

- (NSDictionary *)mainPrefs;
- (BOOL)isEnabled;
- (NSString *)serverAddressInput;            // "notificationServerAddress" field
- (NSDictionary *)appStatus;                 // appStatus dict {bundleId: @YES/@NO}
- (void)setAppStatusValue:(BOOL)value forBundleId:(NSString *)bundleId;
- (void)removeAppStatusForBundleId:(NSString *)bundleId;
- (void)setMainPrefValue:(id)value forKey:(NSString *)key;

// ──────────────────────────────────────────────
// Profile  (com.skyglow.sndp-profile1.plist)
// ──────────────────────────────────────────────

- (NSDictionary *)profile;
- (NSString *)serverAddress;
- (NSString *)deviceAddress;
- (NSString *)serverPubKeyPEM;
- (BOOL)isRegistered;

// ──────────────────────────────────────────────
// Daemon status  (via Unix domain socket)
//
// queryDaemonStatus connects to the StatusServer socket, sends
// SS_MODE_QUERY, reads one SGStatusPayload, and returns it.
//
// On failure (daemon not running, socket not found, version mismatch)
// the returned payload has state = SGStateStarting and all other
// fields zeroed, so callers always get a valid struct.
// ──────────────────────────────────────────────

/// Returns a freshly-queried status payload. Quick (microseconds);
/// safe to call on any thread, including the main thread from loadData:.
- (SGStatusPayload)queryDaemonStatus;

// ──────────────────────────────────────────────
// SQLite: registered tokens  (table: notifications)
// ──────────────────────────────────────────────

- (void)removeAppFromDatabase:(NSString *)bundleId;

/// Removes all tokens (for unregistration cleanup).
/// App preferences (appStatus) are preserved so they survive re-registration.
- (void)clearAllTokens;

/// Returns array of @{@"bundleID": NSString, @"token": NSData, @"routingKey": NSData}
- (NSArray *)allRegisteredTokens;

/// Returns just the set of bundle IDs that have tokens in the database
- (NSSet *)registeredBundleIDs;

/// Number of registered tokens
- (NSInteger)registeredTokenCount;

/// Database file size in bytes
- (unsigned long long)dbFileSize;

// ──────────────────────────────────────────────
// SQLite: DNS cache  (table: dns_cache)
// ──────────────────────────────────────────────

/// Returns @{@"ip": NSString, @"port": NSString} or nil
- (NSDictionary *)cachedDNSForServerAddress:(NSString *)serverAddr;
- (void)clearDNSCache;

// ──────────────────────────────────────────────
// Certificate parsing (OpenSSL)
// ──────────────────────────────────────────────

/// Parses PEM cert string, returns @{@"subject", @"issuer", @"expiry"} or nil
- (NSDictionary *)parseCertificatePEM:(NSString *)pem;

// ──────────────────────────────────────────────
// Unregistration
// ──────────────────────────────────────────────

/// Clears profile, tokens, DNS cache, and tells the daemon to reload.
- (void)unregister;

// ──────────────────────────────────────────────
// Utilities
// ──────────────────────────────────────────────

- (NSString *)hexStringFromData:(NSData *)data;

/// Human-readable label for a daemon state.
- (NSString *)friendlyStringForState:(SGState)state;

/// Colour for a daemon state (green/orange/red/gray).
- (UIColor *)colorForState:(SGState)state;

// ── Legacy wrappers kept for SNLogViewController compatibility ──
// These call through to friendlyStringForState:/colorForState: after
// parsing the old plist-era string constants. New code should use
// the SGState variants above.
- (NSString *)friendlyStatusString:(NSString *)rawStatus;
- (UIColor *)colorForStatus:(NSString *)rawStatus;

@end