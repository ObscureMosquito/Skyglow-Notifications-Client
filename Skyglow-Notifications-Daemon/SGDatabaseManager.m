#import "SGDatabaseManager.h"
#import "SGConfiguration.h"
#import "SGProtocolHandler.h"
#include <sqlite3.h>
#include <sys/stat.h>
#include <unistd.h>

@implementation SGDatabaseManager {
    sqlite3 *_database;
    dispatch_queue_t _databaseQueue;
}

+ (SGDatabaseManager *)sharedManager {
    static SGDatabaseManager *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[self alloc] init];
    });
    return sharedInstance;
}

- (id)init {
    if ((self = [super init])) {
        _databaseQueue = dispatch_queue_create("com.skyglow.database.queue", DISPATCH_QUEUE_SERIAL);

        NSString *dbPath = @"/var/mobile/Library/SkyglowNotifications/sqlite.db";
        NSString *dbDir = [dbPath stringByDeletingLastPathComponent];
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm createDirectoryAtPath:dbDir
      withIntermediateDirectories:YES attributes:nil error:NULL];

        chmod([dbDir UTF8String], 0755);
        chown([dbDir UTF8String], 501, 501);

        if (sqlite3_open([dbPath UTF8String], &_database) != SQLITE_OK) {
            NSLog(@"[SGDatabaseManager] Failed to open database at %@", dbPath);
            [self release];
            return nil;
        }

        chmod([dbPath UTF8String], 0644);
        chown([dbPath UTF8String], 501, 501);

        sqlite3_exec(_database, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
        sqlite3_exec(_database, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);

        char *errorMsg = NULL;
        const char *notifTable = "CREATE TABLE IF NOT EXISTS notifications "
                                 "(routing_key BLOB PRIMARY KEY, e2ee_key BLOB, bundle_id TEXT, token BLOB, "
                                 "is_uploaded INTEGER NOT NULL DEFAULT 1)";
        if (sqlite3_exec(_database, notifTable, NULL, NULL, &errorMsg) != SQLITE_OK) {
            NSLog(@"[SGDatabaseManager] Schema error: %s", errorMsg);
            sqlite3_free(errorMsg);
        }
        
        sqlite3_exec(_database, "ALTER TABLE notifications ADD COLUMN is_uploaded INTEGER NOT NULL DEFAULT 1", NULL, NULL, NULL);

        const char *dnsTable = "CREATE TABLE IF NOT EXISTS dns_cache "
                               "(domain TEXT PRIMARY KEY, ip TEXT NOT NULL, port TEXT NOT NULL, updated_at REAL NOT NULL)";
        sqlite3_exec(_database, dnsTable, NULL, NULL, NULL);

        const char *ackTable = "CREATE TABLE IF NOT EXISTS pending_acks "
                               "(msg_id BLOB PRIMARY KEY, status INTEGER NOT NULL)";
        sqlite3_exec(_database, ackTable, NULL, NULL, NULL);

        const char *settingsTable = "CREATE TABLE IF NOT EXISTS settings "
                                    "(key TEXT PRIMARY KEY, value REAL NOT NULL)";
        sqlite3_exec(_database, settingsTable, NULL, NULL, NULL);

        /**
         * last_delivered_seq: highest device_seq the client has successfully ACK'd.
         * Stored as REAL because SQLite has no native INT64 binding that survives
         * the settings schema — cast to/from int64_t explicitly.
         */
        sqlite3_exec(_database,
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('last_delivered_seq', 0)",
            NULL, NULL, NULL);
    }
    return self;
}

- (void)dealloc {
    if (_database) sqlite3_close(_database);
    if (_databaseQueue) dispatch_release(_databaseQueue);
    [super dealloc];
}

- (void)closeDatabase {
    dispatch_sync(_databaseQueue, ^{
        if (_database) {
            sqlite3_close(_database);
            _database = NULL;
        }
    });
}

- (BOOL)storeDeviceTokenData:(NSData *)routingKey e2eeKey:(NSData *)e2eeKey bundleID:(NSString *)bundleID token:(NSData *)token isUploaded:(BOOL)isUploaded {
    if (!routingKey || !e2eeKey || !bundleID || !token) return NO;

    __block BOOL success = NO;
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "INSERT OR REPLACE INTO notifications (routing_key, e2ee_key, bundle_id, token, is_uploaded) VALUES (?, ?, ?, ?, ?)";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(stmt, 1, [routingKey bytes], (int)[routingKey length], SQLITE_TRANSIENT);
            sqlite3_bind_blob(stmt, 2, [e2eeKey bytes], (int)[e2eeKey length], SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, [bundleID UTF8String], -1, SQLITE_TRANSIENT);
            sqlite3_bind_blob(stmt, 4, [token bytes], (int)[token length], SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 5, isUploaded ? 1 : 0);
            success = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        }
    });
    return success;
}

- (NSArray *)pendingUploadTokens {
    __block NSMutableArray *results = [NSMutableArray array];
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "SELECT routing_key, e2ee_key, bundle_id, token FROM notifications WHERE is_uploaded = 0";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                [results addObject:@{
                    @"routingKey": [NSData dataWithBytes:sqlite3_column_blob(stmt, 0) length:sqlite3_column_bytes(stmt, 0)],
                    @"e2eeKey":    [NSData dataWithBytes:sqlite3_column_blob(stmt, 1) length:sqlite3_column_bytes(stmt, 1)],
                    @"bundleID":   sqlite3_column_text(stmt, 2) ? [NSString stringWithUTF8String:(const char *)sqlite3_column_text(stmt, 2)] : @"",
                    @"token":      [NSData dataWithBytes:sqlite3_column_blob(stmt, 3) length:sqlite3_column_bytes(stmt, 3)]
                }];
            }
            sqlite3_finalize(stmt);
        }
    });
    return results;
}

- (BOOL)markTokenAsUploaded:(NSData *)routingKey {
    __block BOOL ok = NO;
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "UPDATE notifications SET is_uploaded = 1 WHERE routing_key = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(stmt, 1, [routingKey bytes], (int)[routingKey length], SQLITE_TRANSIENT);
            ok = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        }
    });
    return ok;
}

- (void)resetAllTokensToRequireUpload {
    dispatch_sync(_databaseQueue, ^{
        sqlite3_exec(_database, "UPDATE notifications SET is_uploaded = 0", NULL, NULL, NULL);
    });
}

- (NSArray *)tokenEntriesForBundleIdentifier:(NSString *)bundleID {
    __block NSMutableArray *results = [NSMutableArray array];
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "SELECT routing_key, e2ee_key, bundle_id, token FROM notifications WHERE bundle_id = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, [bundleID UTF8String], -1, SQLITE_TRANSIENT);
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                [results addObject:@{
                    @"routingKey": [NSData dataWithBytes:sqlite3_column_blob(stmt, 0) length:sqlite3_column_bytes(stmt, 0)],
                    @"e2eeKey":    [NSData dataWithBytes:sqlite3_column_blob(stmt, 1) length:sqlite3_column_bytes(stmt, 1)],
                    @"bundleID":   sqlite3_column_text(stmt, 2) ? [NSString stringWithUTF8String:(const char *)sqlite3_column_text(stmt, 2)] : @"",
                    @"token":      [NSData dataWithBytes:sqlite3_column_blob(stmt, 3) length:sqlite3_column_bytes(stmt, 3)]
                }];
            }
            sqlite3_finalize(stmt);
        }
    });
    return results;
}

- (BOOL)removeTokenForBundleIdentifier:(NSString *)bundleID {
    __block BOOL ok = NO;
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "DELETE FROM notifications WHERE bundle_id = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, [bundleID UTF8String], -1, SQLITE_TRANSIENT);
            ok = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        }
    });
    return ok;
}

- (NSArray *)allActiveRoutingKeys {
    __block NSMutableArray *results = [NSMutableArray array];
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "SELECT routing_key FROM notifications";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                [results addObject:[NSData dataWithBytes:sqlite3_column_blob(stmt, 0) length:sqlite3_column_bytes(stmt, 0)]];
            }
            sqlite3_finalize(stmt);
        }
    });
    return results;
}

- (NSSet *)registeredBundleIdentifiers {
    __block NSMutableSet *ids = [NSMutableSet set];
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "SELECT DISTINCT bundle_id FROM notifications";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char *bID = (const char *)sqlite3_column_text(stmt, 0);
                if (bID) [ids addObject:[NSString stringWithUTF8String:bID]];
            }
            sqlite3_finalize(stmt);
        }
    });
    return ids;
}

- (NSDictionary *)cachedDNSForDomain:(NSString *)domain maxAge:(NSTimeInterval)maxAge {
    __block NSDictionary *result = nil;
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "SELECT ip, port, updated_at FROM dns_cache WHERE domain = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, [domain UTF8String], -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                double updated = sqlite3_column_double(stmt, 2);
                if ([[NSDate date] timeIntervalSince1970] - updated < maxAge) {
                    result = @{
                        @"tcp_addr": sqlite3_column_text(stmt, 0) ? [NSString stringWithUTF8String:(const char *)sqlite3_column_text(stmt, 0)] : @"",
                        @"tcp_port": sqlite3_column_text(stmt, 1) ? [NSString stringWithUTF8String:(const char *)sqlite3_column_text(stmt, 1)] : @""
                    };
                }
            }
            sqlite3_finalize(stmt);
        }
    });
    return result;
}

- (BOOL)enqueueAcknowledgementForMessageID:(NSData *)msgID status:(int)status {
    __block BOOL ok = NO;
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "INSERT OR REPLACE INTO pending_acks (msg_id, status) VALUES (?, ?)";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(stmt, 1, [msgID bytes], (int)[msgID length], SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 2, status);
            ok = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        }
    });
    return ok;
}

- (NSArray *)pendingAcknowledgements {
    __block NSMutableArray *results = [NSMutableArray array];
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "SELECT msg_id, status FROM pending_acks";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                [results addObject:@{
                    @"msgID": [NSData dataWithBytes:sqlite3_column_blob(stmt, 0) length:sqlite3_column_bytes(stmt, 0)],
                    @"status": @(sqlite3_column_int(stmt, 1))
                }];
            }
            sqlite3_finalize(stmt);
        }
    });
    return results;
}

- (BOOL)removeAcknowledgementForMessageID:(NSData *)msgID {
    __block BOOL ok = NO;
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "DELETE FROM pending_acks WHERE msg_id = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(stmt, 1, [msgID bytes], (int)[msgID length], SQLITE_TRANSIENT);
            ok = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        }
    });
    return ok;
}

- (NSDictionary *)tokenDataForRoutingKey:(NSData *)routingKey {
    if (!routingKey) return nil;
    __block NSDictionary *result = nil;
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "SELECT e2ee_key, bundle_id FROM notifications WHERE routing_key = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(stmt, 1, [routingKey bytes], (int)[routingKey length], SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                result = [@{
                    @"e2eeKey": [NSData dataWithBytes:sqlite3_column_blob(stmt, 0) length:sqlite3_column_bytes(stmt, 0)],
                    @"bundleID": sqlite3_column_text(stmt, 1) ? [NSString stringWithUTF8String:(const char *)sqlite3_column_text(stmt, 1)] : @""
                } retain]; // Retain to survive dispatch_sync
            }
            sqlite3_finalize(stmt);
        }
    });
    return [result autorelease];
}

- (BOOL)storeDNSCacheForDomain:(NSString *)domain ip:(NSString *)ip port:(NSString *)port {
    if (!domain || !ip || !port) return NO;
    __block BOOL ok = NO;
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "INSERT OR REPLACE INTO dns_cache (domain, ip, port, updated_at) VALUES (?, ?, ?, ?)";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, [domain UTF8String], -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, [ip UTF8String], -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, [port UTF8String], -1, SQLITE_TRANSIENT);
            sqlite3_bind_double(stmt, 4, [[NSDate date] timeIntervalSince1970]);
            ok = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        }
    });
    return ok;
}

- (void)saveKeepAliveInterval:(double)interval forWiFi:(BOOL)isWiFi {
    dispatch_async(_databaseQueue, ^{
        const char *sql = "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, isWiFi ? "keepalive_wifi" : "keepalive_wwan", -1, SQLITE_TRANSIENT);
            sqlite3_bind_double(stmt, 2, interval);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    });
}

- (double)loadKeepAliveIntervalForWiFi:(BOOL)isWiFi {
    __block double result = 0.0;
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "SELECT value FROM settings WHERE key = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, isWiFi ? "keepalive_wifi" : "keepalive_wwan", -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                result = sqlite3_column_double(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }
    });
    return result;
}

- (int64_t)lastDeliveredSeq {
    __block int64_t seq = 0;
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "SELECT value FROM settings WHERE key = 'last_delivered_seq'";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                // Stored as double to fit the settings schema; cast back to int64.
                seq = (int64_t)sqlite3_column_double(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }
    });
    return seq;
}

- (void)updateLastDeliveredSeq:(int64_t)seq {
    dispatch_async(_databaseQueue, ^{
        const char *sql = "INSERT OR REPLACE INTO settings (key, value) VALUES ('last_delivered_seq', ?)";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_double(stmt, 1, (double)seq);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    });
}

@end