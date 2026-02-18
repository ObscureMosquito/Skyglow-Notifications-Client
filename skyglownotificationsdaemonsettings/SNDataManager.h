#import <Foundation/Foundation.h>

/// Centralized data access for the Skyglow Notifications settings bundle.
/// All plist reading, plist writing, and SQLite queries go through this singleton.
///
/// This replaces the scattered inline sqlite3/NSDictionary access that was
/// duplicated across every view controller.
@interface SNDataManager : NSObject

+ (SNDataManager *)shared;

// ── Paths ──
@property (nonatomic, readonly) NSString *mainPrefsPath;
@property (nonatomic, readonly) NSString *profilePath;
@property (nonatomic, readonly) NSString *statusPath;
@property (nonatomic, readonly) NSString *dbPath;

// ──────────────────────────────────────────────
// Main preferences  (com.skyglow.sndp.plist)
// ──────────────────────────────────────────────

- (NSDictionary *)mainPrefs;
- (BOOL)isEnabled;
- (NSString *)serverAddressInput;            // "notificationServerAddress" field
- (NSDictionary *)appStatus;                 // appStatus dict {bundleId: @YES/@NO}
- (void)setAppStatusValue:(BOOL)value forBundleId:(NSString *)bundleId;
- (void)setMainPrefValue:(id)value forKey:(NSString *)key;

// ──────────────────────────────────────────────
// Profile  (com.skyglow.sndp-profile1.plist)
// ──────────────────────────────────────────────

- (NSDictionary *)profile;
- (NSString *)serverAddress;                 // Registered server domain (≤16 chars)
- (NSString *)deviceAddress;                 // e.g. user@skyglow.es
- (NSString *)serverPubKeyPEM;               // PEM certificate string
- (BOOL)isRegistered;

// ──────────────────────────────────────────────
// Status  (com.skyglow.sndp.status.plist)
// ──────────────────────────────────────────────

- (NSDictionary *)status;
- (NSString *)connectionStatus;
- (NSDate *)lastUpdated;
- (void)writeStatus:(NSString *)statusString;

// ──────────────────────────────────────────────
// SQLite: registered tokens  (table: notifications)
// ──────────────────────────────────────────────

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

/// Removes profile, disables daemon, writes Disabled status
- (void)unregister;

// ──────────────────────────────────────────────
// Utilities
// ──────────────────────────────────────────────

- (NSString *)hexStringFromData:(NSData *)data;
- (NSString *)friendlyStatusString:(NSString *)rawStatus;
- (UIColor *)colorForStatus:(NSString *)rawStatus;

@end