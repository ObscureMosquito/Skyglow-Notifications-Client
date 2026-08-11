#import "SGDatabaseManager.h"
#import "SGConfiguration.h"
#import "SGLog.h"
#include <sqlite3.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <TargetConditionals.h>

#define SG_DATABASE_APPLICATION_ID 0x53474E44
#define SG_SCHEMA_VERSION 1

#define SG_DEDUP_DEFAULT_RETENTION_SEC ((int64_t)86400)

static sqlite3_int64 SGActiveProfileID(void) {
    NSInteger profile = [[SGConfiguration sharedConfiguration] activeProfileIndex];
    return (sqlite3_int64)((profile >= 1 && profile <= 5) ? profile : 1);
}

static void SGApplyDatabaseOwnership(NSString *path) {
#if !TARGET_OS_OSX
    struct passwd *mobile = getpwnam("mobile");
    if (mobile) {
        (void)chown([path fileSystemRepresentation],
                    mobile->pw_uid, mobile->pw_gid);
    }
#else
    (void)path;
#endif
}

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

        NSString *dbPath = SGPath(SG_DB_PATH);
        NSString *dbDir = [dbPath stringByDeletingLastPathComponent];
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm createDirectoryAtPath:dbDir
      withIntermediateDirectories:YES attributes:nil error:NULL];

        chmod([dbDir fileSystemRepresentation], 0700);
        SGApplyDatabaseOwnership(dbDir);

        if (sqlite3_open([dbPath UTF8String], &_database) != SQLITE_OK) {
            SGLOGE(SGDatabaseManager, "code=%s path=%s result=failed", SGND_DATABASE_OPEN_FAILED, [dbPath UTF8String]);
            [self release];
            return nil;
        }

        sqlite3_busy_timeout(_database, 3000);

        chmod([dbPath fileSystemRepresentation], 0600);
        SGApplyDatabaseOwnership(dbPath);

        sqlite3_exec(_database, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
        sqlite3_exec(_database, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);

        NSString *walPath = [dbPath stringByAppendingString:@"-wal"];
        NSString *shmPath = [dbPath stringByAppendingString:@"-shm"];
        chmod([walPath fileSystemRepresentation], 0600);
        chmod([shmPath fileSystemRepresentation], 0600);
        SGApplyDatabaseOwnership(walPath);
        SGApplyDatabaseOwnership(shmPath);

        if (![self _initializeSchema]) {
            [self release];
            return nil;
        }

        sqlite3_stmt *defaultSeq = NULL;
        BOOL defaultSeqReady = (sqlite3_prepare_v2(_database,
                "INSERT OR IGNORE INTO settings (profile_id, key, value) "
                "VALUES (?, 'last_delivered_seq', 0)",
                -1, &defaultSeq, NULL) == SQLITE_OK);
        if (defaultSeqReady) {
            sqlite3_bind_int64(defaultSeq, 1, SGActiveProfileID());
            defaultSeqReady = (sqlite3_step(defaultSeq) == SQLITE_DONE);
            sqlite3_finalize(defaultSeq);
        }
        if (!defaultSeqReady) {
            SGLOGE(SGDatabaseManager,
                   "code=%s result=failed reason=default_sequence",
                   SGND_DATABASE_SCHEMA_FAILED);
            [self release];
            return nil;
        }
    }
    return self;
}

- (BOOL)_readPragmaInteger:(const char *)pragmaSQL value:(int *)outValue {
    if (!pragmaSQL || !outValue) return NO;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(_database, pragmaSQL, -1, &stmt, NULL) != SQLITE_OK) {
        return NO;
    }
    BOOL ok = (sqlite3_step(stmt) == SQLITE_ROW);
    if (ok) *outValue = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return ok;
}

- (BOOL)_initializeSchema {
    int applicationID = 0;
    int schemaVersion = 0;
    if (![self _readPragmaInteger:"PRAGMA application_id" value:&applicationID] ||
        ![self _readPragmaInteger:"PRAGMA user_version" value:&schemaVersion]) {
        SGLOGE(SGDatabaseManager,
               "code=%s result=failed reason=version_probe",
               SGND_DATABASE_SCHEMA_FAILED);
        return NO;
    }

    if (applicationID == SG_DATABASE_APPLICATION_ID &&
        schemaVersion == SG_SCHEMA_VERSION) {
        return YES;
    }

    /* Dev databases from older builds are rejected; delete and reinstall. */
    if (applicationID != 0 || schemaVersion != 0) {
        SGLOGE(SGDatabaseManager,
               "code=%s result=failed reason=incompatible_unpublished_schema app_id=%d version=%d",
               SGND_DATABASE_SCHEMA_FAILED, applicationID, schemaVersion);
        return NO;
    }

    const char *schema =
        "CREATE TABLE notifications ("
        " profile_id INTEGER NOT NULL,"
        " routing_key BLOB NOT NULL,"
        " e2ee_key BLOB NOT NULL,"
        " bundle_id TEXT NOT NULL,"
        " token BLOB NOT NULL,"
        " is_muted INTEGER NOT NULL DEFAULT 0,"
        " PRIMARY KEY(profile_id, routing_key),"
        " UNIQUE(profile_id, bundle_id));"
        "CREATE TABLE dns_cache ("
        " profile_id INTEGER NOT NULL,"
        " domain TEXT NOT NULL,"
        " ip TEXT NOT NULL,"
        " port TEXT NOT NULL,"
        " updated_at REAL NOT NULL,"
        " PRIMARY KEY(profile_id, domain));"
        "CREATE TABLE pending_acks ("
        " profile_id INTEGER NOT NULL,"
        " msg_id BLOB NOT NULL,"
        " status INTEGER NOT NULL,"
        " PRIMARY KEY(profile_id, msg_id));"
        "CREATE TABLE settings ("
        " profile_id INTEGER NOT NULL,"
        " key TEXT NOT NULL,"
        " value NUMERIC NOT NULL,"
        " PRIMARY KEY(profile_id, key));"
        "CREATE TABLE seen_messages ("
        " profile_id INTEGER NOT NULL,"
        " msg_id BLOB NOT NULL,"
        " expires_at INTEGER NOT NULL,"
        " PRIMARY KEY(profile_id, msg_id));"
        "CREATE TABLE local_pending_deliveries ("
        " profile_id INTEGER NOT NULL,"
        " msg_id BLOB NOT NULL,"
        " bundle_id TEXT NOT NULL,"
        " payload BLOB NOT NULL,"
        " device_seq INTEGER NOT NULL DEFAULT 0,"
        " expires_at INTEGER NOT NULL,"
        " PRIMARY KEY(profile_id, msg_id));"
        "PRAGMA application_id = 1397182020;"
        "PRAGMA user_version = 1;";

    if (sqlite3_exec(_database, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        SGLOGE(SGDatabaseManager,
               "code=%s result=failed reason=begin",
               SGND_DATABASE_SCHEMA_FAILED);
        return NO;
    }

    char *errorMessage = NULL;
    if (sqlite3_exec(_database, schema, NULL, NULL, &errorMessage) != SQLITE_OK) {
        SGLOGE(SGDatabaseManager,
               "code=%s result=failed reason=%s",
               SGND_DATABASE_SCHEMA_FAILED,
               errorMessage ? errorMessage : "(unknown)");
        sqlite3_free(errorMessage);
        sqlite3_exec(_database, "ROLLBACK", NULL, NULL, NULL);
        return NO;
    }

    if (sqlite3_exec(_database, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        SGLOGE(SGDatabaseManager,
               "code=%s result=failed reason=commit",
               SGND_DATABASE_SCHEMA_FAILED);
        sqlite3_exec(_database, "ROLLBACK", NULL, NULL, NULL);
        return NO;
    }
    return YES;
}

- (void)dealloc {
    [self closeDatabase];
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

- (BOOL)storeDeviceTokenData:(NSData *)routingKey e2eeKey:(NSData *)e2eeKey bundleID:(NSString *)bundleID token:(NSData *)token {
    if (!routingKey || !e2eeKey || !bundleID || !token) return NO;

    __block BOOL success = NO;
    dispatch_sync(_databaseQueue, ^{
        sqlite3_int64 profileID = SGActiveProfileID();
        const char *sql = "INSERT OR REPLACE INTO notifications "
                          "(profile_id, routing_key, e2ee_key, bundle_id, token) "
                          "VALUES (?, ?, ?, ?, ?)";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            sqlite3_bind_blob(stmt, 2, [routingKey bytes], (int)[routingKey length], SQLITE_TRANSIENT);
            sqlite3_bind_blob(stmt, 3, [e2eeKey bytes], (int)[e2eeKey length], SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 4, [bundleID UTF8String], -1, SQLITE_TRANSIENT);
            sqlite3_bind_blob(stmt, 5, [token bytes], (int)[token length], SQLITE_TRANSIENT);
            success = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        }
    });
    return success;
}

- (NSArray *)tokenEntriesForBundleIdentifier:(NSString *)bundleID {
    __block NSMutableArray *results = [NSMutableArray array];
    dispatch_sync(_databaseQueue, ^{
        sqlite3_int64 profileID = SGActiveProfileID();
        const char *sql = "SELECT routing_key, e2ee_key, bundle_id, token "
                          "FROM notifications WHERE profile_id = ? AND bundle_id = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            sqlite3_bind_text(stmt, 2, [bundleID UTF8String], -1, SQLITE_TRANSIENT);
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
        sqlite3_int64 profileID = SGActiveProfileID();
        const char *sql = "DELETE FROM notifications WHERE profile_id = ? AND bundle_id = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            sqlite3_bind_text(stmt, 2, [bundleID UTF8String], -1, SQLITE_TRANSIENT);
            ok = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        }
    });
    return ok;
}

- (BOOL)removeAllStateForBundleIdentifier:(NSString *)bundleID {
    if (![bundleID length]) return NO;
    __block BOOL ok = NO;
    dispatch_sync(_databaseQueue, ^{
        if (sqlite3_exec(_database, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
            return;
        }

        sqlite3_stmt *tokens = NULL;
        sqlite3_stmt *deliveries = NULL;
        BOOL tokensReady = (sqlite3_prepare_v2(_database,
            "DELETE FROM notifications WHERE bundle_id = ?",
            -1, &tokens, NULL) == SQLITE_OK);
        BOOL deliveriesReady = (sqlite3_prepare_v2(_database,
            "DELETE FROM local_pending_deliveries WHERE bundle_id = ?",
            -1, &deliveries, NULL) == SQLITE_OK);

        BOOL tokensDeleted = NO;
        BOOL deliveriesDeleted = NO;
        if (tokensReady && deliveriesReady) {
            sqlite3_bind_text(tokens, 1, [bundleID UTF8String],
                              -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(deliveries, 1, [bundleID UTF8String],
                              -1, SQLITE_TRANSIENT);
            tokensDeleted = (sqlite3_step(tokens) == SQLITE_DONE);
            deliveriesDeleted = (sqlite3_step(deliveries) == SQLITE_DONE);
        }
        if (tokens) sqlite3_finalize(tokens);
        if (deliveries) sqlite3_finalize(deliveries);

        if (tokensDeleted && deliveriesDeleted &&
            sqlite3_exec(_database, "COMMIT", NULL, NULL, NULL) == SQLITE_OK) {
            ok = YES;
        } else {
            sqlite3_exec(_database, "ROLLBACK", NULL, NULL, NULL);
        }
    });
    return ok;
}

- (BOOL)clearAllTokens {
    __block BOOL ok = NO;
    dispatch_sync(_databaseQueue, ^{
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(_database,
                "DELETE FROM notifications WHERE profile_id = ?", -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, SGActiveProfileID());
            ok = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        }
    });
    return ok;
}

- (BOOL)clearAllDNSCache {
    __block BOOL ok = NO;
    dispatch_sync(_databaseQueue, ^{
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(_database,
                "DELETE FROM dns_cache WHERE profile_id = ?", -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, SGActiveProfileID());
            ok = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        }
    });
    return ok;
}

- (BOOL)clearOperationalStateForProfile:(NSInteger)profileIndex {
    if (profileIndex < 1 || profileIndex > 5) return NO;
    __block BOOL ok = NO;
    dispatch_sync(_databaseQueue, ^{
        const char *tables[] = {
            "notifications", "dns_cache", "pending_acks", "settings",
            "seen_messages", "local_pending_deliveries"
        };
        ok = (sqlite3_exec(_database, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK);
        for (size_t i = 0; ok && i < sizeof(tables) / sizeof(tables[0]); i++) {
            char sql[128];
            snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE profile_id = ?", tables[i]);
            sqlite3_stmt *stmt = NULL;
            if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) != SQLITE_OK) {
                ok = NO;
                break;
            }
            sqlite3_bind_int64(stmt, 1, (sqlite3_int64)profileIndex);
            ok = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        }
        sqlite3_exec(_database, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
    });
    return ok;
}

- (NSArray *)allBundleRegistrations {
    __block NSMutableArray *results = [NSMutableArray array];
    dispatch_sync(_databaseQueue, ^{
        sqlite3_int64 profileID = SGActiveProfileID();
        const char *sql = "SELECT routing_key, bundle_id, is_muted "
                          "FROM notifications WHERE profile_id = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char *bID = (const char *)sqlite3_column_text(stmt, 1);
                if (!bID) continue;
                [results addObject:@{
                    @"routingKey": [NSData dataWithBytes:sqlite3_column_blob(stmt, 0) length:sqlite3_column_bytes(stmt, 0)],
                    @"bundleID":   [NSString stringWithUTF8String:bID],
                    @"isMuted":    @(sqlite3_column_int(stmt, 2) != 0)
                }];
            }
            sqlite3_finalize(stmt);
        }
    });
    return results;
}

- (BOOL)setMuted:(BOOL)muted forBundleIdentifier:(NSString *)bundleID {
    if (!bundleID) return NO;
    __block BOOL ok = NO;
    dispatch_sync(_databaseQueue, ^{
        sqlite3_int64 profileID = SGActiveProfileID();
        const char *sql = "UPDATE notifications SET is_muted = ? "
                          "WHERE profile_id = ? AND bundle_id = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, muted ? 1 : 0);
            sqlite3_bind_int64(stmt, 2, profileID);
            sqlite3_bind_text(stmt, 3, [bundleID UTF8String], -1, SQLITE_TRANSIENT);
            ok = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        }
    });
    return ok;
}

- (BOOL)isMutedForRoutingKey:(NSData *)routingKey {
    if (!routingKey) return NO;
    __block BOOL muted = NO;
    dispatch_sync(_databaseQueue, ^{
        sqlite3_int64 profileID = SGActiveProfileID();
        const char *sql = "SELECT is_muted FROM notifications "
                          "WHERE profile_id = ? AND routing_key = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            sqlite3_bind_blob(stmt, 2, [routingKey bytes], (int)[routingKey length], SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                muted = (sqlite3_column_int(stmt, 0) != 0);
            }
            sqlite3_finalize(stmt);
        }
    });
    return muted;
}

- (NSSet *)registeredBundleIdentifiers {
    __block NSMutableSet *ids = [NSMutableSet set];
    dispatch_sync(_databaseQueue, ^{
        sqlite3_int64 profileID = SGActiveProfileID();
        const char *sql = "SELECT DISTINCT bundle_id FROM notifications WHERE profile_id = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
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
        sqlite3_int64 profileID = SGActiveProfileID();
        const char *sql = "SELECT ip, port, updated_at FROM dns_cache "
                          "WHERE profile_id = ? AND domain = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            sqlite3_bind_text(stmt, 2, [domain UTF8String], -1, SQLITE_TRANSIENT);
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
    sqlite3_int64 profileID = SGActiveProfileID();
    __block BOOL ok = NO;
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "INSERT OR REPLACE INTO pending_acks "
                          "(profile_id, msg_id, status) VALUES (?, ?, ?)";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            sqlite3_bind_blob(stmt, 2, [msgID bytes], (int)[msgID length], SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 3, status);
            ok = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        }
    });
    return ok;
}

- (NSArray *)pendingAcknowledgements {
    __block NSMutableArray *results = [NSMutableArray array];
    dispatch_sync(_databaseQueue, ^{
        sqlite3_int64 profileID = SGActiveProfileID();
        const char *sql = "SELECT msg_id, status FROM pending_acks WHERE profile_id = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
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
    sqlite3_int64 profileID = SGActiveProfileID();
    __block BOOL ok = NO;
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "DELETE FROM pending_acks WHERE profile_id = ? AND msg_id = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            sqlite3_bind_blob(stmt, 2, [msgID bytes], (int)[msgID length], SQLITE_TRANSIENT);
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
        sqlite3_int64 profileID = SGActiveProfileID();
        const char *sql = "SELECT e2ee_key, bundle_id FROM notifications "
                          "WHERE profile_id = ? AND routing_key = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            sqlite3_bind_blob(stmt, 2, [routingKey bytes], (int)[routingKey length], SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                result = [@{
                    @"e2eeKey": [NSData dataWithBytes:sqlite3_column_blob(stmt, 0) length:sqlite3_column_bytes(stmt, 0)],
                    @"bundleID": sqlite3_column_text(stmt, 1) ? [NSString stringWithUTF8String:(const char *)sqlite3_column_text(stmt, 1)] : @""
                } retain];
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
        sqlite3_int64 profileID = SGActiveProfileID();
        const char *sql = "INSERT OR REPLACE INTO dns_cache "
                          "(profile_id, domain, ip, port, updated_at) VALUES (?, ?, ?, ?, ?)";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            sqlite3_bind_text(stmt, 2, [domain UTF8String], -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, [ip UTF8String], -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 4, [port UTF8String], -1, SQLITE_TRANSIENT);
            sqlite3_bind_double(stmt, 5, [[NSDate date] timeIntervalSince1970]);
            ok = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        }
    });
    return ok;
}

- (void)saveKeepAliveInterval:(double)interval forWiFi:(BOOL)isWiFi {
    sqlite3_int64 profileID = SGActiveProfileID();
    dispatch_async(_databaseQueue, ^{
        const char *sql = "INSERT OR REPLACE INTO settings "
                          "(profile_id, key, value) VALUES (?, ?, ?)";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            sqlite3_bind_text(stmt, 2, isWiFi ? "keepalive_wifi" : "keepalive_wwan", -1, SQLITE_TRANSIENT);
            sqlite3_bind_double(stmt, 3, interval);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    });
}

- (double)loadKeepAliveIntervalForWiFi:(BOOL)isWiFi {
    __block double result = 0.0;
    dispatch_sync(_databaseQueue, ^{
        sqlite3_int64 profileID = SGActiveProfileID();
        const char *sql = "SELECT value FROM settings WHERE profile_id = ? AND key = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            sqlite3_bind_text(stmt, 2, isWiFi ? "keepalive_wifi" : "keepalive_wwan", -1, SQLITE_TRANSIENT);
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
        sqlite3_int64 profileID = SGActiveProfileID();
        const char *sql = "SELECT value FROM settings "
                          "WHERE profile_id = ? AND key = 'last_delivered_seq'";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                seq = sqlite3_column_int64(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }
    });
    return seq;
}

- (void)updateLastDeliveredSeq:(int64_t)seq {
    sqlite3_int64 profileID = SGActiveProfileID();
    dispatch_async(_databaseQueue, ^{
        const char *sql = "INSERT OR REPLACE INTO settings "
                          "(profile_id, key, value) VALUES (?, 'last_delivered_seq', ?)";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            sqlite3_bind_int64(stmt, 2, seq);
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
        sqlite3_int64 profileID = SGActiveProfileID();
        const char *sql = "SELECT 1 FROM seen_messages "
                          "WHERE profile_id = ? AND msg_id = ? LIMIT 1";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            sqlite3_bind_blob(stmt, 2, [msgID bytes], (int)[msgID length], SQLITE_TRANSIENT);
            seen = (sqlite3_step(stmt) == SQLITE_ROW);
            sqlite3_finalize(stmt);
        }
    });
    return seen;
}

- (void)markMessageIDAsSeen:(NSData *)msgID expiresAt:(int64_t)expiresAt {
    if (!msgID || [msgID length] == 0) return;
    int64_t now = (int64_t)time(NULL);
    int64_t effective = (expiresAt > now) ? expiresAt : (now + SG_DEDUP_DEFAULT_RETENTION_SEC);
    sqlite3_int64 profileID = SGActiveProfileID();
    dispatch_async(_databaseQueue, ^{
        const char *sql = "INSERT OR REPLACE INTO seen_messages "
                          "(profile_id, msg_id, expires_at) VALUES (?, ?, ?)";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            sqlite3_bind_blob(stmt, 2, [msgID bytes], (int)[msgID length], SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 3, effective);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    });
}

- (void)pruneExpiredSeenMessagesAsOf:(int64_t)nowEpoch {
    sqlite3_int64 profileID = SGActiveProfileID();
    dispatch_async(_databaseQueue, ^{
        const char *sql = "DELETE FROM seen_messages "
                          "WHERE profile_id = ? AND expires_at < ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            sqlite3_bind_int64(stmt, 2, nowEpoch);
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
    sqlite3_int64 profileID = SGActiveProfileID();
    __block BOOL ok = NO;
    dispatch_sync(_databaseQueue, ^{
        const char *sql = "INSERT OR REPLACE INTO local_pending_deliveries "
                          "(profile_id, msg_id, bundle_id, payload, device_seq, expires_at) "
                          "VALUES (?, ?, ?, ?, ?, ?)";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            sqlite3_bind_blob(stmt, 2, [msgID bytes], (int)[msgID length], SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, [bundleID UTF8String], -1, SQLITE_TRANSIENT);
            sqlite3_bind_blob(stmt, 4, [serializedPayload bytes], (int)[serializedPayload length], SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 5, deviceSeq);
            sqlite3_bind_int64(stmt, 6, expiresAt);
            ok = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        }
    });
    return ok;
}

- (NSArray *)allLocalPendingDeliveries {
    __block NSMutableArray *results = [NSMutableArray array];
    dispatch_sync(_databaseQueue, ^{
        sqlite3_int64 profileID = SGActiveProfileID();
        const char *sql = "SELECT msg_id, bundle_id, payload, device_seq, expires_at "
                          "FROM local_pending_deliveries WHERE profile_id = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
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
        sqlite3_int64 profileID = SGActiveProfileID();
        const char *sql = "DELETE FROM local_pending_deliveries "
                          "WHERE profile_id = ? AND msg_id = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            sqlite3_bind_blob(stmt, 2, [msgID bytes], (int)[msgID length], SQLITE_TRANSIENT);
            ok = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        }
    });
    return ok;
}

- (BOOL)removeLocalPendingDeliveriesForBundleIdentifier:(NSString *)bundleID {
    if (!bundleID || [bundleID length] == 0) return NO;
    __block BOOL ok = NO;
    dispatch_sync(_databaseQueue, ^{
        sqlite3_int64 profileID = SGActiveProfileID();
        const char *sql = "DELETE FROM local_pending_deliveries "
                          "WHERE profile_id = ? AND bundle_id = ?";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            sqlite3_bind_text(stmt, 2, [bundleID UTF8String], -1, SQLITE_TRANSIENT);
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
        sqlite3_int64 profileID = SGActiveProfileID();
        const char *sql = "SELECT 1 FROM local_pending_deliveries "
                          "WHERE profile_id = ? AND msg_id = ? LIMIT 1";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(self->_database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, profileID);
            sqlite3_bind_blob(stmt, 2, [msgID bytes], (int)[msgID length], SQLITE_TRANSIENT);
            present = (sqlite3_step(stmt) == SQLITE_ROW);
            sqlite3_finalize(stmt);
        }
    });
    return present;
}

@end
