#import "SNDataManager.h"
#import <UIKit/UIKit.h>
#import <sqlite3.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static NSString *const kMainPrefsPath  = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
static NSString *const kProfilePath    = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
static NSString *const kDBPath         = @"/var/mobile/Library/SkyglowNotifications/sqlite.db";

@interface SNDataManager ()
@property (nonatomic, assign) NSInteger watchCount;
@property (nonatomic, assign) int watchSocketFD;
@property (nonatomic, assign) BOOL isWatching;
@end

@implementation SNDataManager

+ (SNDataManager *)shared {
    static SNDataManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ instance = [[SNDataManager alloc] init]; });
    return instance;
}

- (NSString *)mainPrefsPath { return kMainPrefsPath; }
- (NSString *)profilePath   { return kProfilePath; }
- (NSString *)dbPath        { return kDBPath; }

// --- Main Preferences ---
- (NSDictionary *)mainPrefs { return [NSDictionary dictionaryWithContentsOfFile:kMainPrefsPath] ?: @{}; }
- (BOOL)isEnabled { return [[[self mainPrefs] objectForKey:@"enabled"] boolValue]; }

- (NSDictionary *)appStatus { return [[self mainPrefs] objectForKey:@"appStatus"] ?: @{}; }

- (void)setAppStatusValue:(BOOL)value forBundleId:(NSString *)bundleId {
    if (!bundleId) return;
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:kMainPrefsPath] ?: [NSMutableDictionary dictionary];
    NSMutableDictionary *appSt = [NSMutableDictionary dictionaryWithDictionary:[prefs objectForKey:@"appStatus"] ?: @{}];
    [appSt setObject:@(value) forKey:bundleId];
    [prefs setObject:appSt forKey:@"appStatus"];
    [prefs writeToFile:kMainPrefsPath atomically:YES];
}

- (void)removeAppStatusForBundleId:(NSString *)bundleId {
    if (!bundleId) return;
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:kMainPrefsPath] ?: [NSMutableDictionary dictionary];
    NSMutableDictionary *appSt = [NSMutableDictionary dictionaryWithDictionary:[prefs objectForKey:@"appStatus"] ?: @{}];
    [appSt removeObjectForKey:bundleId];
    [prefs setObject:appSt forKey:@"appStatus"];
    [prefs writeToFile:kMainPrefsPath atomically:YES];
}

- (NSString *)serverAddressInput {
    // Returns the raw text the user typed into the preferences bundle
    return [[self mainPrefs] objectForKey:@"notificationServerAddress"];
}

- (void)clearDNSCache {
    sqlite3 *db = NULL;
    if (sqlite3_open([kDBPath UTF8String], &db) == SQLITE_OK) {
        sqlite3_exec(db, "DELETE FROM dns_cache;", NULL, NULL, NULL);
        sqlite3_close(db);
    }
}

- (void)clearAllTokens {
    sqlite3 *db = NULL;
    if (sqlite3_open([kDBPath UTF8String], &db) == SQLITE_OK) {
        sqlite3_exec(db, "DELETE FROM notifications;", NULL, NULL, NULL);
        sqlite3_close(db);
    }
}

- (void)setMainPrefValue:(id)value forKey:(NSString *)key {
    if (!key) return;
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:kMainPrefsPath] ?: [NSMutableDictionary dictionary];
    if (value) [prefs setObject:value forKey:key]; else [prefs removeObjectForKey:key];
    [prefs writeToFile:kMainPrefsPath atomically:YES];
}

// --- Profile ---
- (NSDictionary *)profile { return [NSDictionary dictionaryWithContentsOfFile:kProfilePath] ?: @{}; }
- (NSString *)serverAddress   { return [[self profile] objectForKey:@"server_address"]; }
- (NSString *)deviceAddress   { return [[self profile] objectForKey:@"device_address"]; }
- (NSString *)serverPubKeyPEM { return [[self profile] objectForKey:@"server_pub_key"]; }
- (BOOL)isRegistered { return ([self serverAddress] != nil && [[self serverAddress] length] > 0); }

// --- Daemon Status via Unix Socket ---
- (SGStatusPayload)queryDaemonStatus {
    SGStatusPayload empty;
    memset(&empty, 0, sizeof(empty));
    
    BOOL isEnabled = NO;
    FILE *pidFile = fopen("/var/run/skyglow_daemon.pid", "r");
    if (pidFile) {
        int pid = 0;
        if (fscanf(pidFile, "%d", &pid) == 1 && pid > 0) {
            // kill with signal 0 checks if the process exists without sending a signal
            if (kill(pid, 0) == 0) isEnabled = YES;
        }
        fclose(pidFile);
    }
    
    empty.state = isEnabled ? SGStateStarting : SGStateDisabled;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return empty;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strlcpy(addr.sun_path, SS_SOCKET_PATH, sizeof(addr.sun_path));

    struct timeval tv = {0, 300000}; // 300ms timeout so the UI never freezes
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { 
        close(fd); 
        return empty; 
    }

    uint8_t mode = SS_MODE_QUERY;
    if (write(fd, &mode, 1) != 1) { 
        close(fd); 
        return empty; 
    }

    SGStatusPayload payload;
    memset(&payload, 0, sizeof(payload));
    ssize_t total = 0, remaining = (ssize_t)sizeof(payload);
    uint8_t *buf = (uint8_t *)&payload;

    // Read the exact size of the packed struct
    while (remaining > 0) {
        ssize_t n = read(fd, buf + total, (size_t)remaining);
        if (n <= 0) break;
        total += n; 
        remaining -= n;
    }
    close(fd);

    // If we read the exact expected bytes, the payload is valid
    if (total == (ssize_t)sizeof(payload)) {
        return payload;
    }
    
    return empty;
}

- (void)startWatchingDaemonStatus {
    self.watchCount++;
    if (self.watchCount > 1) return;
    
    self.latestPayload = [self queryDaemonStatus];
    [[NSNotificationCenter defaultCenter] postNotificationName:@"SNDaemonStatusUpdated" object:nil];
    
    self.isWatching = YES;
    self.watchSocketFD = -1;
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        while (self.isWatching) {
            int fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (fd < 0) { sleep(1); continue; }
            self.watchSocketFD = fd;
            
            struct sockaddr_un addr;
            memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;
            strlcpy(addr.sun_path, SS_SOCKET_PATH, sizeof(addr.sun_path));
            
            if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
                close(fd);
                self.watchSocketFD = -1;
                
                dispatch_async(dispatch_get_main_queue(), ^{
                    BOOL isEnabled = NO;
                    FILE *pidFile = fopen("/var/run/skyglow_daemon.pid", "r");
                    if (pidFile) {
                        int pid = 0;
                        if (fscanf(pidFile, "%d", &pid) == 1 && pid > 0) {
                            if (kill(pid, 0) == 0) isEnabled = YES;
                        }
                        fclose(pidFile);
                    }
                    
                    SGStatusPayload empty;
                    memset(&empty, 0, sizeof(empty));
                    empty.state = isEnabled ? SGStateStarting : SGStateDisabled;
                    if (self.latestPayload.state != empty.state) {
                        self.latestPayload = empty;
                        [[NSNotificationCenter defaultCenter] postNotificationName:@"SNDaemonStatusUpdated" object:nil];
                    }
                });
                
                sleep(1);
                continue;
            }
            
            uint8_t mode = 0x57; // SS_MODE_WATCH
            if (write(fd, &mode, 1) != 1) {
                close(fd);
                self.watchSocketFD = -1;
                sleep(1);
                continue;
            }
            
            while (self.isWatching) {
                SGStatusPayload payload;
                memset(&payload, 0, sizeof(payload));
                ssize_t total = 0, remaining = sizeof(payload);
                uint8_t *buf = (uint8_t *)&payload;
                
                while (remaining > 0) {
                    ssize_t n = read(fd, buf + total, remaining);
                    if (n <= 0) break;
                    total += n;
                    remaining -= n;
                }
                
                if (total == sizeof(payload)) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        self.latestPayload = payload;
                        [[NSNotificationCenter defaultCenter] postNotificationName:@"SNDaemonStatusUpdated" object:nil];
                    });
                } else {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        BOOL isEnabled = NO;
                        FILE *pidFile = fopen("/var/run/skyglow_daemon.pid", "r");
                        if (pidFile) {
                            int pid = 0;
                            if (fscanf(pidFile, "%d", &pid) == 1 && pid > 0) {
                                if (kill(pid, 0) == 0) isEnabled = YES;
                            }
                            fclose(pidFile);
                        }
                        
                        SGStatusPayload empty;
                        memset(&empty, 0, sizeof(empty));
                        empty.state = isEnabled ? SGStateStarting : SGStateDisabled;
                        if (self.latestPayload.state != empty.state) {
                            self.latestPayload = empty;
                            [[NSNotificationCenter defaultCenter] postNotificationName:@"SNDaemonStatusUpdated" object:nil];
                        }
                    });
                    break;
                }
            }
            
            close(fd);
            self.watchSocketFD = -1;
            sleep(1);
        }
    });
}

- (void)stopWatchingDaemonStatus {
    self.watchCount--;
    if (self.watchCount <= 0) {
        self.watchCount = 0;
        self.isWatching = NO;
        if (self.watchSocketFD >= 0) {
            close(self.watchSocketFD);
            self.watchSocketFD = -1;
        }
    }
}

// --- SQLite ---
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
    if (sqlite3_prepare_v2(db, "SELECT bundle_id, token, routing_key FROM notifications ORDER BY bundle_id ASC", -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *bID = (const char *)sqlite3_column_text(stmt, 0);
            const void *tData = sqlite3_column_blob(stmt, 1);
            int tLen = sqlite3_column_bytes(stmt, 1);
            const void *rData = sqlite3_column_blob(stmt, 2);
            int rLen = sqlite3_column_bytes(stmt, 2);
            if (bID) {
                [results addObject:@{
                    @"bundleID": [NSString stringWithUTF8String:bID],
                    @"token": (tData && tLen > 0) ? [NSData dataWithBytes:tData length:tLen] : [NSData data],
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
    if (sqlite3_prepare_v2(db, "SELECT DISTINCT bundle_id FROM notifications", -1, &stmt, NULL) == SQLITE_OK) {
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
    if (sqlite3_prepare_v2(db, "SELECT count(*) FROM notifications", -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) count = sqlite3_column_int(stmt, 0);
    }
    if (stmt) sqlite3_finalize(stmt);
    sqlite3_close(db);
    return count;
}

- (unsigned long long)dbFileSize {
    return [[[NSFileManager defaultManager] attributesOfItemAtPath:kDBPath error:nil] fileSize];
}

- (void)removeAppFromDatabase:(NSString *)bundleId {
    if (!bundleId) return;
    sqlite3 *db = NULL;
    if (sqlite3_open([kDBPath UTF8String], &db) == SQLITE_OK) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db, "DELETE FROM notifications WHERE bundle_id = ?", -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, [bundleId UTF8String], -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
        }
        if (stmt) sqlite3_finalize(stmt);
    }
    if (db) sqlite3_close(db);
}

- (NSDictionary *)cachedDNSForServerAddress:(NSString *)serverAddr {
    if (!serverAddr) return nil;
    sqlite3 *db = openDBReadOnly();
    if (!db) return nil;
    NSString *dnsKey = [NSString stringWithFormat:@"_sgn.%@", serverAddr];
    NSDictionary *result = nil;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT ip, port FROM dns_cache WHERE domain = ?", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, [dnsKey UTF8String], -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *ip = (const char *)sqlite3_column_text(stmt, 0);
            const char *port = (const char *)sqlite3_column_text(stmt, 1);
            if (ip && port) result = @{@"ip": [NSString stringWithUTF8String:ip], @"port": [NSString stringWithUTF8String:port]};
        }
    }
    if (stmt) sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

// --- Certificate Parsing ---
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
        int idx = X509_NAME_get_index_by_NID(subjectName, NID_commonName, -1);
        if (idx >= 0) {
            ASN1_STRING *data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subjectName, idx));
            unsigned char *utf8 = NULL;
            if (ASN1_STRING_to_UTF8(&utf8, data) > 0 && utf8) {
                [info setObject:[NSString stringWithUTF8String:(char *)utf8] forKey:@"subject"];
                OPENSSL_free(utf8);
            }
        }
    }

    X509_NAME *issuerName = X509_get_issuer_name(cert);
    if (issuerName) {
        int idx = X509_NAME_get_index_by_NID(issuerName, NID_organizationName, -1);
        if (idx >= 0) {
            ASN1_STRING *data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(issuerName, idx));
            unsigned char *utf8 = NULL;
            if (ASN1_STRING_to_UTF8(&utf8, data) > 0 && utf8) {
                [info setObject:[NSString stringWithUTF8String:(char *)utf8] forKey:@"issuer"];
                OPENSSL_free(utf8);
            }
        }
    }

    X509_free(cert);
    return info;
}

// --- Unregistration ---
- (void)unregisterDevice {
    // 1. Delete Profile Plist (Removes Device Address & Server Keys)
    [[NSFileManager defaultManager] removeItemAtPath:kProfilePath error:nil];

    // 2. Wipe cryptographic tokens and DNS, but KEEP appStatus in the main plist!
    sqlite3 *db = NULL;
    if (sqlite3_open([kDBPath UTF8String], &db) == SQLITE_OK) {
        sqlite3_exec(db, "DELETE FROM notifications;", NULL, NULL, NULL);
        sqlite3_exec(db, "DELETE FROM dns_cache;", NULL, NULL, NULL);
    }
    if (db) sqlite3_close(db);

    // 3. Inform the daemon to disconnect and reload config
    CFNotificationCenterPostNotificationWithOptions(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("com.skyglow.sgn.reload_config"), NULL, NULL, kCFNotificationDeliverImmediately);
}

// --- Utilities ---
- (NSString *)hexStringFromData:(NSData *)data {
    if (!data || [data length] == 0) return @"";
    const unsigned char *bytes = (const unsigned char *)[data bytes];
    NSMutableString *hex = [NSMutableString stringWithCapacity:([data length] * 2)];
    for (NSUInteger i = 0; i < [data length]; i++) [hex appendFormat:@"%02x", bytes[i]];
    return hex;
}

- (NSString *)friendlyStringForState:(SGState)state {
    switch (state) {
        case SGStateConnected:         return @"Connected";
        case SGStateAuthenticating:    return @"Authenticating…";
        case SGStateConnecting:        return @"Connecting…";
        case SGStateResolvingDNS:      return @"Resolving DNS…";
        case SGStateBackingOff:        return @"Reconnecting…";
        case SGStateIdleNoNetwork:     return @"No Network";
        case SGStateIdleDNSFailed:     return @"DNS Failed";
        case SGStateIdleCircuitOpen:   return @"Paused (Too Many Errors)";
        case SGStateIdleUnregistered:  return @"Waiting for Config";
        case SGStateDisabled:          return @"Disabled";
        case SGStateErrorAuth:         return @"Auth Error";
        case SGStateErrorBadConfig:    return @"Bad Config";
        case SGStateError:             return @"Error";
        case SGStateStarting:          return @"Starting…";
        case SGStateShuttingDown:      return @"Shutting Down";
        default:                       return @"Unknown";
    }
}

- (UIColor *)colorForState:(SGState)state {
    switch (state) {
        case SGStateConnected: return [UIColor colorWithRed:0.2 green:0.7 blue:0.2 alpha:1.0];
        case SGStateConnecting: case SGStateAuthenticating: case SGStateResolvingDNS: case SGStateBackingOff: return [UIColor orangeColor];
        case SGStateIdleNoNetwork: case SGStateIdleCircuitOpen: case SGStateIdleDNSFailed: return [UIColor colorWithRed:0.9 green:0.6 blue:0.1 alpha:1.0];
        case SGStateErrorAuth: case SGStateErrorBadConfig: case SGStateError: return [UIColor colorWithRed:0.85 green:0.2 blue:0.2 alpha:1.0];
        default: return [UIColor grayColor];
    }
}

@end