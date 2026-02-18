#import "SNDataManager.h"
#import <UIKit/UIKit.h>
#import <sqlite3.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>

// ──────────────────────────────────────────────
// File paths (constants)
// ──────────────────────────────────────────────

static NSString *const kMainPrefsPath  = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
static NSString *const kProfilePath    = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
static NSString *const kStatusPath     = @"/var/mobile/Library/Preferences/com.skyglow.sndp.status.plist";
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
- (NSString *)statusPath    { return kStatusPath; }
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
#pragma mark - Status
// ══════════════════════════════════════════════

- (NSDictionary *)status {
    return [NSDictionary dictionaryWithContentsOfFile:kStatusPath] ?: @{};
}

- (NSString *)connectionStatus {
    return [[self status] objectForKey:@"currentStatus"];
}

- (NSDate *)lastUpdated {
    return [[self status] objectForKey:@"lastUpdated"];
}

- (void)writeStatus:(NSString *)statusString {
    NSDictionary *dict = @{
                           @"lastUpdated":   [NSDate date],
                           @"currentStatus": statusString ?: @"Unknown"
                           };
    [dict writeToFile:kStatusPath atomically:YES];
}

// ══════════════════════════════════════════════
#pragma mark - SQLite: Tokens
// ══════════════════════════════════════════════

/// Opens the database read-only; caller must close.
/// Returns NULL on failure.
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
    
    // ── The daemon's table is "notifications", NOT "registrations" ──
    const char *sql = "SELECT bundle_id, token, routing_key FROM notifications ORDER BY bundle_id ASC";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *bID   = (const char *)sqlite3_column_text(stmt, 0);
            const void *tData = sqlite3_column_blob(stmt, 1);
            int         tLen  = sqlite3_column_bytes(stmt, 1);
            const void *rData = sqlite3_column_blob(stmt, 2);
            int         rLen  = sqlite3_column_bytes(stmt, 2);
            
            if (bID) {
                NSString *bundleID  = [NSString stringWithUTF8String:bID];
                NSData   *token     = (tData && tLen > 0) ? [NSData dataWithBytes:tData length:tLen] : [NSData data];
                NSData   *routingKey = (rData && rLen > 0) ? [NSData dataWithBytes:rData length:rLen] : [NSData data];
                [results addObject:@{
                                     @"bundleID":   bundleID,
                                     @"token":      token,
                                     @"routingKey": routingKey
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
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            count = sqlite3_column_int(stmt, 0);
        }
    }
    if (stmt) sqlite3_finalize(stmt);
    sqlite3_close(db);
    return count;
}

- (unsigned long long)dbFileSize {
    NSDictionary *attrs = [[NSFileManager defaultManager]
                           attributesOfItemAtPath:kDBPath error:nil];
    return [attrs fileSize];
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
                           @"port": [NSString stringWithUTF8String:port]
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
    
    // ── Subject (prefer CN) ──
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
    
    // ── Issuer (prefer O) ──
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
    
    // ── Expiry ──
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
    
    // Remove profile
    [fm removeItemAtPath:kProfilePath error:nil];
    
    // Disable
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:kMainPrefsPath]
    ?: [NSMutableDictionary dictionary];
    [prefs setObject:@NO forKey:@"enabled"];
    [prefs writeToFile:kMainPrefsPath atomically:YES];
    
    // Write status
    [self writeStatus:@"Disabled"];
    
    // Notify daemon
    CFNotificationCenterPostNotificationWithOptions(
                                                    CFNotificationCenterGetDarwinNotifyCenter(),
                                                    CFSTR("com.skyglow.snd.request_update"),
                                                    NULL, NULL,
                                                    kCFNotificationDeliverImmediately);
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

- (NSString *)friendlyStatusString:(NSString *)status {
    if (!status) return @"Unknown";
    if ([status isEqualToString:@"Connected"])                  return @"Connected";
    if ([status isEqualToString:@"ConnectedNotAuthenticated"])  return @"Authenticating…";
    if ([status isEqualToString:@"EnabledNotConnected"])        return @"Connecting…";
    if ([status isEqualToString:@"Disabled"])                   return @"Disabled";
    if ([status isEqualToString:@"Error"])                      return @"Error";
    if ([status isEqualToString:@"ErrorInAuth"])                return @"Auth Error";
    if ([status isEqualToString:@"ServerConfigBad"])            return @"Bad Config";
    if ([status isEqualToString:@"ConnectionClosed"])           return @"Disconnected";
    if ([status isEqualToString:@"FatalConnectionError"])       return @"Fatal Error";
    if ([status isEqualToString:@"DaemonStatusConnectionClosed"]) return @"Connection Closed";
    return status;
}

- (UIColor *)colorForStatus:(NSString *)status {
    if (!status) return [UIColor grayColor];
    if ([status isEqualToString:@"Connected"])
        return [UIColor colorWithRed:0.2 green:0.7 blue:0.2 alpha:1.0];
    if ([status isEqualToString:@"Disabled"])
        return [UIColor grayColor];
    if ([status isEqualToString:@"EnabledNotConnected"] ||
        [status isEqualToString:@"ConnectedNotAuthenticated"])
        return [UIColor orangeColor];
    if ([status isEqualToString:@"Error"] ||
        [status isEqualToString:@"ErrorInAuth"] ||
        [status isEqualToString:@"ServerConfigBad"] ||
        [status isEqualToString:@"FatalConnectionError"])
        return [UIColor redColor];
    return [UIColor darkGrayColor];
}

@end