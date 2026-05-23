#import "SGDatabaseManager.h"
#import "SGConfiguration.h"
#import "SGProtocolHandler.h"
#import "SGLog.h"
#include <sqlite3.h>
#include <sys/stat.h>
#include <unistd.h>

/**
 * SQLite schema version of this build.  Incremented whenever a migration is
 * added below.  Pre-versioning databases (anything older than v1) are tagged
 * as v1 in-place — the inline CREATE IF NOT EXISTS calls in -init already
 * produce that exact schema for both fresh and upgraded databases.
 */
#define SG_SCHEMA_LATEST_VERSION 3

/**
 * Local retention floor for the seen_messages dedup table.  Notifications
 * without a server-supplied expires_at, or whose expiry has already passed by
 * the time we record them, are kept for this long so a late retransmit from
 * the server can still be recognised as a duplicate.
 */
#define SG_DEDUP_DEFAULT_RETENTION_SEC ((int64_t)86400)

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

        NSString *dbPath = SGPath(@"/var/mobile/Library/SkyglowNotifications/sqlite.db");
        NSString *dbDir = [dbPath stringByDeletingLastPathComponent];
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm createDirectoryAtPath:dbDir
      withIntermediateDirectories:YES attributes:nil error:NULL];

        chmod([dbDir UTF8String], 0755);
        chown([dbDir UTF8String], 501, 501);

        if (sqlite3_open([dbPath UTF8String], &_database) != SQLITE_OK) {
            SGLOGE(SGDatabaseManager, "Failed to open database at %s", [dbPath UTF8String]);
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
            SGLOGE(SGDatabaseManager, "Schema error: %s", errorMsg ? errorMsg : "(null)");
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

        [self _migrateSchema];
    }
    return self;
}

/**
 * Brings the database from whatever PRAGMA user_version it currently reports
 * up to SG_SCHEMA_LATEST_VERSION by running migrations in sequence.  Each step
 * is wrapped in an immediate transaction so a partial failure rolls back and
 * the migration is retried on the next launch.  PRAGMA user_version is the
 * canonical built-in counter — available on every SQLite version Apple has
 * ever shipped — so we do not need a dedicated schema_version table.
 */
- (void)_migrateSchema {
    int currentVersion = 0;
    sqlite3_stmt *probe = NULL;
    if (sqlite3_prepare_v2(_database, "PRAGMA user_version", -1, &probe, NULL) == SQLITE_OK) {
        if (sqlite3_step(probe) == SQLITE_ROW) currentVersion = sqlite3_column_int(probe, 0);
        sqlite3_finalize(probe);
    }

    while (currentVersion < SG_SCHEMA_LATEST_VERSION) {
        int targetVersion = currentVersion + 1;
        const char *migration = NULL;

        switch (targetVersion) {
            case 1:
                /**
                 * v1 codifies the schema produced by the inline CREATE IF NOT
                 * EXISTS calls above.  Both fresh databases (user_version=0
                 * before this migration ran) and existing databases (also 0
                 * because PRAGMA user_version has never been set before) reach
                 * the same shape at this point — no DDL needed, just stamp it.
                 */
                migration = NULL;
                break;
            case 2:
                /**
                 * Durable dedup of received notifications.  Survives daemon
                 * restarts and reconnects so a server retransmit after we have
                 * already delivered a notification does not produce a duplicate
                 * banner on the device.
                 */
                migration =
                    "CREATE TABLE IF NOT EXISTS seen_messages "
                    "(msg_id BLOB PRIMARY KEY, expires_at INTEGER NOT NULL)";
                break;
            case 3:
                /**
                 * Local-side delivery retry queue.  Holds notifications whose
                 * Mach delivery to SpringBoard failed (tweak unloaded, SB
                 * restarting) so the daemon can redeliver without ever ACKing
                 * the server for a banner it did not surface.
                 */
                migration =
                    "CREATE TABLE IF NOT EXISTS local_pending_deliveries "
                    "(msg_id BLOB PRIMARY KEY, bundle_id TEXT NOT NULL, "
                    "payload BLOB NOT NULL, device_seq INTEGER NOT NULL DEFAULT 0, "
                    "expires_at INTEGER NOT NULL)";
                break;
        }

        sqlite3_exec(_database, "BEGIN IMMEDIATE", NULL, NULL, NULL);
        int rc = SQLITE_OK;
        if (migration) {
            char *err = NULL;
            rc = sqlite3_exec(_database, migration, NULL, NULL, &err);
            if (rc != SQLITE_OK) {
                SGLOGE(SGDatabaseManager, "Schema migration %d -> %d failed: %s",
                       currentVersion, targetVersion, err ? err : "(null)");
                sqlite3_free(err);
                sqlite3_exec(_database, "ROLLBACK", NULL, NULL, NULL);
                return;
            }
        }

        char stamp[64];
        snprintf(stamp, sizeof(stamp), "PRAGMA user_version = %d", targetVersion);
        sqlite3_exec(_database, stamp, NULL, NULL, NULL);
        sqlite3_exec(_database, "COMMIT", NULL, NULL, NULL);

        SGLOGI(SGDatabaseManager, "Schema migrated %d -> %d.", currentVersion, targetVersion);
        currentVersion = targetVersion;
    }
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

- (void)checkpoint {
    dispatch_async(_databaseQueue, ^{
        if (self->_database) {
            sqlite3_wal_checkpoint_v2(self->_database, NULL, SQLITE_CHECKPOINT_PASSIVE, NULL, NULL);
        }
    });
}

- (BOOL)hasSeenMessageID:(NSData *)msgID {
    if (!msgID || [msgID length] == 0) return NO;
    __block BOOL seen = NO;
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "SELECT 1 FROM seen_messages WHERE msg_id = ? LIMIT 1";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(stmt, 1, [msgID bytes], (int)[msgID length], SQLITE_TRANSIENT);
            seen = (sqlite3_step(stmt) == SQLITE_ROW);
            sqlite3_finalize(stmt);
        }
    });
    return seen;
}

- (void)markMessageIDAsSeen:(NSData *)msgID expiresAt:(int64_t)expiresAt {
    if (!msgID || [msgID length] == 0) return;
    int64_t now = (int64_t)time(NULL);
    /**
     * If the wire expiry is missing or already past, keep the row long enough
     * to suppress retransmits that arrive while the server's redelivery timer
     * is still running.  A flat 24h floor is generous compared to typical APNS
     * resend windows (minutes) and costs trivial storage.
     */
    int64_t effective = (expiresAt > now) ? expiresAt : (now + SG_DEDUP_DEFAULT_RETENTION_SEC);
    dispatch_async(_databaseQueue, ^{
        const char *sql = "INSERT OR REPLACE INTO seen_messages (msg_id, expires_at) VALUES (?, ?)";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(stmt, 1, [msgID bytes], (int)[msgID length], SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 2, effective);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    });
}

- (void)pruneExpiredSeenMessagesAsOf:(int64_t)nowEpoch {
    dispatch_async(_databaseQueue, ^{
        const char *sql = "DELETE FROM seen_messages WHERE expires_at < ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, nowEpoch);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    });
}

- (BOOL)enqueueLocalPendingDeliveryForMessageID:(NSData *)msgID
                                       bundleID:(NSString *)bundleID
                                        payload:(NSData *)serializedPayload
                                      deviceSeq:(int64_t)deviceSeq
                                      expiresAt:(int64_t)expiresAt {
    if (!msgID || [msgID length] == 0 || !bundleID || !serializedPayload) return NO;
    __block BOOL ok = NO;
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "INSERT OR REPLACE INTO local_pending_deliveries "
                          "(msg_id, bundle_id, payload, device_seq, expires_at) "
                          "VALUES (?, ?, ?, ?, ?)";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(stmt, 1, [msgID bytes], (int)[msgID length], SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, [bundleID UTF8String], -1, SQLITE_TRANSIENT);
            sqlite3_bind_blob(stmt, 3, [serializedPayload bytes], (int)[serializedPayload length], SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 4, deviceSeq);
            sqlite3_bind_int64(stmt, 5, expiresAt);
            ok = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        }
    });
    return ok;
}

- (NSArray *)allLocalPendingDeliveries {
    __block NSMutableArray *results = [NSMutableArray array];
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "SELECT msg_id, bundle_id, payload, device_seq, expires_at FROM local_pending_deliveries";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char *bID = (const char *)sqlite3_column_text(stmt, 1);
                [results addObject:@{
                    @"msgID":     [NSData dataWithBytes:sqlite3_column_blob(stmt, 0) length:sqlite3_column_bytes(stmt, 0)],
                    @"bundleID":  bID ? [NSString stringWithUTF8String:bID] : @"",
                    @"payload":   [NSData dataWithBytes:sqlite3_column_blob(stmt, 2) length:sqlite3_column_bytes(stmt, 2)],
                    @"deviceSeq": [NSNumber numberWithLongLong:sqlite3_column_int64(stmt, 3)],
                    @"expiresAt": [NSNumber numberWithLongLong:sqlite3_column_int64(stmt, 4)]
                }];
            }
            sqlite3_finalize(stmt);
        }
    });
    return results;
}

- (BOOL)removeLocalPendingDeliveryForMessageID:(NSData *)msgID {
    if (!msgID || [msgID length] == 0) return NO;
    __block BOOL ok = NO;
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "DELETE FROM local_pending_deliveries WHERE msg_id = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(stmt, 1, [msgID bytes], (int)[msgID length], SQLITE_TRANSIENT);
            ok = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        }
    });
    return ok;
}

- (BOOL)hasLocalPendingDeliveryForMessageID:(NSData *)msgID {
    if (!msgID || [msgID length] == 0) return NO;
    __block BOOL present = NO;
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "SELECT 1 FROM local_pending_deliveries WHERE msg_id = ? LIMIT 1";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(stmt, 1, [msgID bytes], (int)[msgID length], SQLITE_TRANSIENT);
            present = (sqlite3_step(stmt) == SQLITE_ROW);
            sqlite3_finalize(stmt);
        }
    });
    return present;
}

@end