#import "SNDataManager.h"
#import <UIKit/UIKit.h>
#import <sqlite3.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

// ──────────────────────────────────────────────
// File paths (constants)
// ──────────────────────────────────────────────

static NSString *const kMainPrefsPath  = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
static NSString *const kProfilePath    = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
static NSString *const kDBPath         = @"/var/mobile/Library/SkyglowNotifications/sqlite.db";

@implementation SNDataManager

// ──────────────────────────────────────────────
// Singleton
// ──────────────────────────────────────────────

+ (SNDataManager *)shared {
    static SNDataManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[SNDataManager alloc] init];
    });
    return instance;
}

- (NSString *)mainPrefsPath { return kMainPrefsPath; }
- (NSString *)profilePath   { return kProfilePath; }
- (NSString *)dbPath        { return kDBPath; }

// ══════════════════════════════════════════════
#pragma mark - Main Preferences
// ══════════════════════════════════════════════

- (NSDictionary *)mainPrefs {
    return [NSDictionary dictionaryWithContentsOfFile:kMainPrefsPath] ?: @{};
}

- (BOOL)isEnabled {
    return [[[self mainPrefs] objectForKey:@"enabled"] boolValue];
}

- (NSString *)serverAddressInput {
    return [[self mainPrefs] objectForKey:@"notificationServerAddress"] ?: @"";
}

- (NSDictionary *)appStatus {
    return [[self mainPrefs] objectForKey:@"appStatus"] ?: @{};
}

- (void)setAppStatusValue:(BOOL)value forBundleId:(NSString *)bundleId {
    if (!bundleId) return;
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:kMainPrefsPath]
        ?: [NSMutableDictionary dictionary];
    NSMutableDictionary *appSt = [NSMutableDictionary dictionaryWithDictionary:
                                  [prefs objectForKey:@"appStatus"] ?: @{}];
    [appSt setObject:@(value) forKey:bundleId];
    [prefs setObject:appSt forKey:@"appStatus"];
    [prefs writeToFile:kMainPrefsPath atomically:YES];
}

- (void)setMainPrefValue:(id)value forKey:(NSString *)key {
    if (!key) return;
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:kMainPrefsPath]
        ?: [NSMutableDictionary dictionary];
    if (value)
        [prefs setObject:value forKey:key];
    else
        [prefs removeObjectForKey:key];
    [prefs writeToFile:kMainPrefsPath atomically:YES];
}

- (void)removeAppStatusForBundleId:(NSString *)bundleId {
    if (!bundleId) return;
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:kMainPrefsPath]
        ?: [NSMutableDictionary dictionary];
    NSMutableDictionary *appSt = [NSMutableDictionary dictionaryWithDictionary:
                                  [prefs objectForKey:@"appStatus"] ?: @{}];
    [appSt removeObjectForKey:bundleId];
    [prefs setObject:appSt forKey:@"appStatus"];
    [prefs writeToFile:kMainPrefsPath atomically:YES];
}

// ══════════════════════════════════════════════
#pragma mark - Profile
// ══════════════════════════════════════════════

- (NSDictionary *)profile {
    return [NSDictionary dictionaryWithContentsOfFile:kProfilePath] ?: @{};
}

- (NSString *)serverAddress   { return [[self profile] objectForKey:@"server_address"]; }
- (NSString *)deviceAddress   { return [[self profile] objectForKey:@"device_address"]; }
- (NSString *)serverPubKeyPEM { return [[self profile] objectForKey:@"server_pub_key"]; }

- (BOOL)isRegistered {
    NSString *addr = [self serverAddress];
    return (addr != nil && [addr length] > 0);
}

// ══════════════════════════════════════════════
#pragma mark - Daemon Status (socket)
// ══════════════════════════════════════════════

- (SGStatusPayload)queryDaemonStatus {
    // Return a safe zero payload on any failure so callers never see
    // garbage. State = SGStateStarting reads as "daemon not yet heard
    // from" which is a reasonable fallback.
    SGStatusPayload empty;
    memset(&empty, 0, sizeof(empty));
    empty.magic   = SS_PAYLOAD_MAGIC;
    empty.version = SS_PAYLOAD_VERSION;
    empty.state   = SGStateStarting;

    // ── Open socket ──────────────────────────────────────────────
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return empty;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strlcpy(addr.sun_path, SS_SOCKET_PATH, sizeof(addr.sun_path));

    // Non-blocking connect with a short timeout so the UI never hangs
    // if the daemon is restarting.
    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = 300000; // 300 ms
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return empty;
    }

    // ── Send mode byte ───────────────────────────────────────────
    uint8_t mode = SS_MODE_QUERY;
    if (write(fd, &mode, 1) != 1) {
        close(fd);
        return empty;
    }

    // ── Read payload ─────────────────────────────────────────────
    SGStatusPayload payload;
    memset(&payload, 0, sizeof(payload));

    ssize_t total = 0;
    ssize_t remaining = (ssize_t)sizeof(payload);
    uint8_t *buf = (uint8_t *)&payload;

    while (remaining > 0) {
        ssize_t n = read(fd, buf + total, (size_t)remaining);
        if (n <= 0) break; // timeout, EOF, or error
        total     += n;
        remaining -= n;
    }

    close(fd);

    if (total != (ssize_t)sizeof(payload)) return empty;
    if (payload.magic   != SS_PAYLOAD_MAGIC)   return empty;
    if (payload.version != SS_PAYLOAD_VERSION) return empty;

    return payload;
}

// ══════════════════════════════════════════════
#pragma mark - SQLite: Tokens
// ══════════════════════════════════════════════

static sqlite3 *openDBReadOnly(void) {
    sqlite3 *db = NULL;
    if (![[NSFileManager defaultManager] fileExistsAtPath:kDBPath]) return NULL;
    if (sqlite3_open_v2([kDBPath UTF8String], &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return NULL;
    }
    return db;
}

- (NSArray *)allRegisteredTokens {
    sqlite3 *db = openDBReadOnly();
    if (!db) return @[];

    NSMutableArray *results = [NSMutableArray array];
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT bundle_id, token, routing_key FROM notifications ORDER BY bundle_id ASC";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *bID   = (const char *)sqlite3_column_text(stmt, 0);
            const void *tData = sqlite3_column_blob(stmt, 1);
            int         tLen  = sqlite3_column_bytes(stmt, 1);
            const void *rData = sqlite3_column_blob(stmt, 2);
            int         rLen  = sqlite3_column_bytes(stmt, 2);

            if (bID) {
                [results addObject:@{
                    @"bundleID":   [NSString stringWithUTF8String:bID],
                    @"token":      (tData && tLen > 0) ? [NSData dataWithBytes:tData length:tLen] : [NSData data],
                    @"routingKey": (rData && rLen > 0) ? [NSData dataWithBytes:rData length:rLen] : [NSData data],
                }];
            }
        }
    }
    if (stmt) sqlite3_finalize(stmt);
    sqlite3_close(db);
    return results;
}

- (NSSet *)registeredBundleIDs {
    sqlite3 *db = openDBReadOnly();
    if (!db) return [NSSet set];

    NSMutableSet *ids = [NSMutableSet set];
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT DISTINCT bundle_id FROM notifications";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *bID = (const char *)sqlite3_column_text(stmt, 0);
            if (bID) [ids addObject:[NSString stringWithUTF8String:bID]];
        }
    }
    if (stmt) sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ids;
}

- (NSInteger)registeredTokenCount {
    sqlite3 *db = openDBReadOnly();
    if (!db) return 0;

    NSInteger count = 0;
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT count(*) FROM notifications";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW)
            count = sqlite3_column_int(stmt, 0);
    }
    if (stmt) sqlite3_finalize(stmt);
    sqlite3_close(db);
    return count;
}

- (unsigned long long)dbFileSize {
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:kDBPath error:nil];
    return [attrs fileSize];
}

- (void)removeAppFromDatabase:(NSString *)bundleId {
    if (!bundleId) return;
    sqlite3 *db = NULL;
    if (sqlite3_open([kDBPath UTF8String], &db) == SQLITE_OK) {
        const char *sql = "DELETE FROM notifications WHERE bundle_id = ?";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, [bundleId UTF8String], -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
        }
        if (stmt) sqlite3_finalize(stmt);
    }
    if (db) sqlite3_close(db);
}

- (void)clearAllTokens {
    sqlite3 *db = NULL;
    if (sqlite3_open([kDBPath UTF8String], &db) == SQLITE_OK) {
        sqlite3_exec(db, "DELETE FROM notifications;", NULL, NULL, NULL);
        NSLog(@"[SNDataManager] Cleared all tokens from database");
    }
    if (db) sqlite3_close(db);
}

// ══════════════════════════════════════════════
#pragma mark - SQLite: DNS Cache
// ══════════════════════════════════════════════

- (NSDictionary *)cachedDNSForServerAddress:(NSString *)serverAddr {
    if (!serverAddr) return nil;
    sqlite3 *db = openDBReadOnly();
    if (!db) return nil;

    NSString *dnsKey = [NSString stringWithFormat:@"_sgn.%@", serverAddr];
    NSDictionary *result = nil;
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT ip, port FROM dns_cache WHERE domain = ?";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, [dnsKey UTF8String], -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *ip   = (const char *)sqlite3_column_text(stmt, 0);
            const char *port = (const char *)sqlite3_column_text(stmt, 1);
            if (ip && port) {
                result = @{
                    @"ip":   [NSString stringWithUTF8String:ip],
                    @"port": [NSString stringWithUTF8String:port],
                };
            }
        }
    }
    if (stmt) sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

- (void)clearDNSCache {
    sqlite3 *db = NULL;
    if (sqlite3_open([kDBPath UTF8String], &db) == SQLITE_OK) {
        sqlite3_exec(db, "DELETE FROM dns_cache;", NULL, NULL, NULL);
    }
    if (db) sqlite3_close(db);
}

// ══════════════════════════════════════════════
#pragma mark - Certificate Parsing
// ══════════════════════════════════════════════

- (NSDictionary *)parseCertificatePEM:(NSString *)pem {
    if (!pem || [pem length] == 0) return nil;

    BIO *bio = BIO_new_mem_buf((void *)[pem UTF8String], -1);
    if (!bio) return nil;

    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cert) return nil;

    NSMutableDictionary *info = [NSMutableDictionary dictionary];

    X509_NAME *subjectName = X509_get_subject_name(cert);
    if (subjectName) {
        NSString *cn = [self extractNID:NID_commonName fromName:subjectName];
        if (cn) {
            [info setObject:cn forKey:@"subject"];
        } else {
            char buf[512];
            X509_NAME_oneline(subjectName, buf, sizeof(buf));
            [info setObject:[NSString stringWithUTF8String:buf] forKey:@"subject"];
        }
    }

    X509_NAME *issuerName = X509_get_issuer_name(cert);
    if (issuerName) {
        NSString *org = [self extractNID:NID_organizationName fromName:issuerName];
        if (org) {
            [info setObject:org forKey:@"issuer"];
        } else {
            char buf[512];
            X509_NAME_oneline(issuerName, buf, sizeof(buf));
            [info setObject:[NSString stringWithUTF8String:buf] forKey:@"issuer"];
        }
    }

    ASN1_TIME *notAfter = X509_get_notAfter(cert);
    if (notAfter) {
        BIO *timeBio = BIO_new(BIO_s_mem());
        if (timeBio) {
            ASN1_TIME_print(timeBio, notAfter);
            char timeBuf[128];
            int readLen = BIO_read(timeBio, timeBuf, sizeof(timeBuf) - 1);
            if (readLen > 0) {
                timeBuf[readLen] = '\0';
                [info setObject:[NSString stringWithUTF8String:timeBuf] forKey:@"expiry"];
            }
            BIO_free(timeBio);
        }
    }

    X509_free(cert);
    return [info count] > 0 ? info : nil;
}

- (NSString *)extractNID:(int)nid fromName:(X509_NAME *)name {
    int idx = X509_NAME_get_index_by_NID(name, nid, -1);
    if (idx < 0) return nil;

    X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, idx);
    ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
    if (!data) return nil;

    unsigned char *utf8 = NULL;
    int len = ASN1_STRING_to_UTF8(&utf8, data);
    if (len <= 0 || !utf8) return nil;

    NSString *result = [NSString stringWithUTF8String:(char *)utf8];
    OPENSSL_free(utf8);
    return result;
}

// ══════════════════════════════════════════════
#pragma mark - Unregistration
// ══════════════════════════════════════════════

- (void)unregister {
    NSFileManager *fm = [NSFileManager defaultManager];

    // 1. Remove profile (keys, server address, device address)
    [fm removeItemAtPath:kProfilePath error:nil];

    // 2. Clear all tokens — they're tied to the old device identity
    //    and won't work after re-registration with a new keypair.
    //    NOTE: appStatus in main plist is preserved so app toggle
    //    preferences survive re-registration.
    [self clearAllTokens];

    // 3. Clear DNS cache — server may change on re-register
    [self clearDNSCache];

    // NOTE: We do NOT set enabled=NO here. The daemon stays enabled
    // but idle (no server to connect to). The user can re-register
    // without having to manually re-enable.

    // 4. Tell daemon to re-read config and disconnect gracefully
    //    (daemon will send ClientDisconnect before closing socket)
    CFNotificationCenterPostNotificationWithOptions(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFSTR("com.skyglow.snd.reload_config"),
        NULL, NULL, kCFNotificationDeliverImmediately);

    // 5. Post UI refresh notification so other view controllers update
    CFNotificationCenterPostNotificationWithOptions(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFSTR("com.skyglow.snd.request_update"),
        NULL, NULL, kCFNotificationDeliverImmediately);
}

// ══════════════════════════════════════════════
#pragma mark - Utilities
// ══════════════════════════════════════════════

- (NSString *)hexStringFromData:(NSData *)data {
    if (!data || [data length] == 0) return @"";
    const unsigned char *bytes = (const unsigned char *)[data bytes];
    NSMutableString *hex = [NSMutableString stringWithCapacity:([data length] * 2)];
    for (NSUInteger i = 0; i < [data length]; i++) {
        [hex appendFormat:@"%02x", (unsigned int)bytes[i]];
    }
    return hex;
}

// ──────────────────────────────────────────────
// SGState-based display helpers
// ──────────────────────────────────────────────

- (NSString *)friendlyStringForState:(SGState)state {
    switch (state) {
        case SGStateStarting:          return @"Starting…";
        case SGStateDisabled:          return @"Disabled";
        case SGStateIdleUnregistered:  return @"Not Registered";
        case SGStateResolvingDNS:      return @"Resolving DNS…";
        case SGStateIdleDNSFailed:     return @"DNS Failed";
        case SGStateConnecting:        return @"Connecting…";
        case SGStateAuthenticating:    return @"Authenticating…";
        case SGStateConnected:         return @"Connected";
        case SGStateBackingOff:        return @"Reconnecting…";
        case SGStateIdleNoNetwork:     return @"No Network";
        case SGStateIdleCircuitOpen:   return @"Paused (Too Many Errors)";
        case SGStateErrorAuth:         return @"Auth Error";
        case SGStateErrorBadConfig:    return @"Bad Config";
        case SGStateError:             return @"Error";
        case SGStateShuttingDown:      return @"Shutting Down";
        default:                       return @"Unknown";
    }
}

- (UIColor *)colorForState:(SGState)state {
    switch (state) {
        case SGStateConnected:
            return [UIColor colorWithRed:0.2 green:0.7 blue:0.2 alpha:1.0]; // green

        case SGStateConnecting:
        case SGStateAuthenticating:
        case SGStateResolvingDNS:
        case SGStateBackingOff:
            return [UIColor orangeColor]; // in-progress

        case SGStateIdleNoNetwork:
        case SGStateIdleCircuitOpen:
        case SGStateIdleDNSFailed:
            return [UIColor colorWithRed:0.9 green:0.6 blue:0.1 alpha:1.0]; // amber

        case SGStateErrorAuth:
        case SGStateErrorBadConfig:
        case SGStateError:
            return [UIColor colorWithRed:0.85 green:0.2 blue:0.2 alpha:1.0]; // red

        case SGStateDisabled:
        case SGStateIdleUnregistered:
        case SGStateStarting:
        case SGStateShuttingDown:
        default:
            return [UIColor grayColor];
    }
}

// ──────────────────────────────────────────────
// Legacy string-based wrappers (for SNLogViewController)
//
// SNLogViewController currently reads plist strings directly and calls
// these. They map the old status string constants to the new SGState
// equivalents so we don't have to rewrite SNLogViewController in this
// pass. New callers should use friendlyStringForState:/colorForState:
// directly.
// ──────────────────────────────────────────────

- (NSString *)friendlyStatusString:(NSString *)status {
    if (!status) return [self friendlyStringForState:SGStateStarting];
    if ([status isEqualToString:@"Connected"])               return [self friendlyStringForState:SGStateConnected];
    if ([status isEqualToString:@"ConnectedNotAuthenticated"]) return [self friendlyStringForState:SGStateAuthenticating];
    if ([status isEqualToString:@"EnabledNotConnected"])     return [self friendlyStringForState:SGStateConnecting];
    if ([status isEqualToString:@"EnabledNotRegistered"])    return [self friendlyStringForState:SGStateIdleUnregistered];
    if ([status isEqualToString:@"Disabled"])                return [self friendlyStringForState:SGStateDisabled];
    if ([status isEqualToString:@"Error"])                   return [self friendlyStringForState:SGStateError];
    if ([status isEqualToString:@"ErrorInAuth"])             return [self friendlyStringForState:SGStateErrorAuth];
    if ([status isEqualToString:@"ServerConfigBad"])         return [self friendlyStringForState:SGStateErrorBadConfig];
    if ([status isEqualToString:@"ConnectionClosed"])        return [self friendlyStringForState:SGStateBackingOff];
    return status; // unknown — pass through
}

- (UIColor *)colorForStatus:(NSString *)status {
    if (!status) return [self colorForState:SGStateStarting];
    if ([status isEqualToString:@"Connected"])               return [self colorForState:SGStateConnected];
    if ([status isEqualToString:@"ConnectedNotAuthenticated"]) return [self colorForState:SGStateAuthenticating];
    if ([status isEqualToString:@"EnabledNotConnected"])     return [self colorForState:SGStateConnecting];
    if ([status isEqualToString:@"EnabledNotRegistered"])    return [self colorForState:SGStateIdleUnregistered];
    if ([status isEqualToString:@"Disabled"])                return [self colorForState:SGStateDisabled];
    if ([status isEqualToString:@"Error"])                   return [self colorForState:SGStateError];
    if ([status isEqualToString:@"ErrorInAuth"])             return [self colorForState:SGStateErrorAuth];
    if ([status isEqualToString:@"ServerConfigBad"])         return [self colorForState:SGStateErrorBadConfig];
    if ([status isEqualToString:@"ConnectionClosed"])        return [self colorForState:SGStateBackingOff];
    return [UIColor darkGrayColor];
}

@end