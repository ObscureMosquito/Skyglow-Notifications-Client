#import "DBManager.h"
#include <Foundation/Foundation.h>

@implementation DBManager

+ (DBManager *)sharedStorage {
    static DBManager *shared = nil;
    @synchronized(self) {
        if (!shared) {
            shared = [[self alloc] init];
        }
    }
    return shared;
}

- (id)init {
    if ((self = [super init])) {
        NSString *dbPath = @"/var/mobile/Library/SkyglowNotifications/sqlite.db";
        NSFileManager *fm = [NSFileManager defaultManager];

        [fm createDirectoryAtPath:[dbPath stringByDeletingLastPathComponent]
      withIntermediateDirectories:YES
                       attributes:nil
                            error:NULL];

        NSDictionary *attrs = @{
            NSFileOwnerAccountID:      @(501),
            NSFileGroupOwnerAccountID: @(501)
        };
        [fm setAttributes:attrs ofItemAtPath:[dbPath stringByDeletingLastPathComponent] error:nil];

        if (sqlite3_open([dbPath UTF8String], &database) != SQLITE_OK) {
            NSLog(@"[DBManager] Failed to open database at %@", dbPath);
            [self release];
            return nil;
        }

        sqlite3_exec(database, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);

        char *errorMsg = NULL;

        const char *sql1 = "CREATE TABLE IF NOT EXISTS notifications "
                           "(routing_key BLOB PRIMARY KEY, e2ee_key BLOB, bundle_id TEXT, token BLOB)";
        if (sqlite3_exec(database, sql1, NULL, NULL, &errorMsg) != SQLITE_OK) {
            NSLog(@"[DBManager] Error creating notifications table: %s", errorMsg);
            sqlite3_free(errorMsg);
        }

        const char *sql2 = "CREATE TABLE IF NOT EXISTS dns_cache "
                           "(domain TEXT PRIMARY KEY, ip TEXT NOT NULL, port TEXT NOT NULL, "
                           "updated_at REAL NOT NULL)";
        if (sqlite3_exec(database, sql2, NULL, NULL, &errorMsg) != SQLITE_OK) {
            NSLog(@"[DBManager] Error creating dns_cache table: %s", errorMsg);
            sqlite3_free(errorMsg);
        }
    }
    return self;
}

// ──────────────────────────────────────────────
// Token storage
// ──────────────────────────────────────────────

- (BOOL)storeTokenData:(NSData *)routingKey
               e2eeKey:(NSData *)e2eeKey
              bundleID:(NSString *)bundleID
                 token:(NSData *)token {

    if (!routingKey || !e2eeKey || !bundleID || !token) return NO;

    @synchronized(self) {
        const char *sql = "INSERT OR REPLACE INTO notifications VALUES (?, ?, ?, ?)";
        sqlite3_stmt *stmt;

        if (sqlite3_prepare_v2(database, sql, -1, &stmt, NULL) != SQLITE_OK) {
            NSLog(@"[DBManager] store prepare: %s", sqlite3_errmsg(database));
            return NO;
        }

        sqlite3_bind_blob(stmt, 1, [routingKey bytes], (int)[routingKey length], SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 2, [e2eeKey bytes],    (int)[e2eeKey length],    SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, [bundleID UTF8String], -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 4, [token bytes],       (int)[token length],     SQLITE_TRANSIENT);

        BOOL ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }
}

- (NSDictionary *)dataForRoutingKey:(NSData *)routingKey {
    if (!routingKey) return nil;

    @synchronized(self) {
        const char *sql = "SELECT routing_key, e2ee_key, bundle_id FROM notifications WHERE routing_key = ?";
        sqlite3_stmt *stmt;
        NSDictionary *result = nil;

        if (sqlite3_prepare_v2(database, sql, -1, &stmt, NULL) != SQLITE_OK) return nil;

        sqlite3_bind_blob(stmt, 1, [routingKey bytes], (int)[routingKey length], SQLITE_TRANSIENT);

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const void *rkBytes  = sqlite3_column_blob(stmt, 0);
            int         rkLen    = sqlite3_column_bytes(stmt, 0);
            const void *e2Bytes  = sqlite3_column_blob(stmt, 1);
            int         e2Len    = sqlite3_column_bytes(stmt, 1);
            const char *bidChars = (const char *)sqlite3_column_text(stmt, 2);

            NSData   *rk  = [NSData dataWithBytes:rkBytes length:rkLen];
            NSData   *e2  = [NSData dataWithBytes:e2Bytes length:e2Len];
            NSString *bid = bidChars ? [NSString stringWithUTF8String:bidChars] : nil;

            result = @{
                @"routingKey": rk,
                @"e2eeKey":    e2,
                @"bundleID":   bid ?: [NSNull null]
            };
        }
        sqlite3_finalize(stmt);
        return result;
    }
}

- (NSArray *)dataForBundleID:(NSString *)bundleID {
    if (!bundleID) return @[];

    @synchronized(self) {
        const char *sql = "SELECT routing_key, e2ee_key, bundle_id, token FROM notifications WHERE bundle_id = ?";
        sqlite3_stmt *stmt;
        NSMutableArray *results = [NSMutableArray array];

        if (sqlite3_prepare_v2(database, sql, -1, &stmt, NULL) != SQLITE_OK) return results;

        sqlite3_bind_text(stmt, 1, [bundleID UTF8String], -1, SQLITE_TRANSIENT);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void *rkBytes  = sqlite3_column_blob(stmt, 0);
            int         rkLen    = sqlite3_column_bytes(stmt, 0);
            const void *e2Bytes  = sqlite3_column_blob(stmt, 1);
            int         e2Len    = sqlite3_column_bytes(stmt, 1);
            const char *bidChars = (const char *)sqlite3_column_text(stmt, 2);
            const void *tkBytes  = sqlite3_column_blob(stmt, 3);
            int         tkLen    = sqlite3_column_bytes(stmt, 3);

            [results addObject:@{
                @"routingKey": [NSData dataWithBytes:rkBytes length:rkLen],
                @"e2eeKey":    [NSData dataWithBytes:e2Bytes length:e2Len],
                @"bundleID":   bidChars ? [NSString stringWithUTF8String:bidChars] : [NSNull null],
                @"token":      [NSData dataWithBytes:tkBytes length:tkLen]
            }];
        }
        sqlite3_finalize(stmt);
        return results;
    }
}

- (BOOL)removeTokenWithBundleId:(NSString *)bundleID {
    if (!bundleID) return NO;

    @synchronized(self) {
        const char *sql = "DELETE FROM notifications WHERE bundle_id = ?";
        sqlite3_stmt *stmt;

        if (sqlite3_prepare_v2(database, sql, -1, &stmt, NULL) != SQLITE_OK) {
            NSLog(@"[DBManager] delete prepare: %s", sqlite3_errmsg(database));
            return NO;
        }

        sqlite3_bind_text(stmt, 1, [bundleID UTF8String], -1, SQLITE_TRANSIENT);

        BOOL ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }
}

// ──────────────────────────────────────────────
// DNS cache
// ──────────────────────────────────────────────

- (NSDictionary *)cachedDNSForDomain:(NSString *)domain maxAgeSeconds:(NSTimeInterval)maxAge {
    if (!domain) return nil;

    @synchronized(self) {
        const char *sql = "SELECT ip, port, updated_at FROM dns_cache WHERE domain = ?";
        sqlite3_stmt *stmt;

        if (sqlite3_prepare_v2(database, sql, -1, &stmt, NULL) != SQLITE_OK) return nil;

        sqlite3_bind_text(stmt, 1, [domain UTF8String], -1, SQLITE_TRANSIENT);

        NSDictionary *result = nil;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *ipChars   = (const char *)sqlite3_column_text(stmt, 0);
            const char *portChars = (const char *)sqlite3_column_text(stmt, 1);
            double updatedAt      = sqlite3_column_double(stmt, 2);

            NSTimeInterval age = [[NSDate date] timeIntervalSince1970] - updatedAt;
            if (age < maxAge && ipChars && portChars) {
                result = @{
                    @"tcp_addr": [NSString stringWithUTF8String:ipChars],
                    @"tcp_port": [NSString stringWithUTF8String:portChars],
                    @"cached":   @YES,
                    @"age":      @(age)
                };
            }
        }
        sqlite3_finalize(stmt);
        return result;
    }
}

- (BOOL)storeDNSCache:(NSString *)domain ip:(NSString *)ip port:(NSString *)port {
    if (!domain || !ip || !port) return NO;

    @synchronized(self) {
        const char *sql = "INSERT OR REPLACE INTO dns_cache (domain, ip, port, updated_at) VALUES (?, ?, ?, ?)";
        sqlite3_stmt *stmt;

        if (sqlite3_prepare_v2(database, sql, -1, &stmt, NULL) != SQLITE_OK) {
            NSLog(@"[DBManager] dns_cache prepare: %s", sqlite3_errmsg(database));
            return NO;
        }

        double now = [[NSDate date] timeIntervalSince1970];
        sqlite3_bind_text(stmt,   1, [domain UTF8String], -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt,   2, [ip UTF8String],     -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt,   3, [port UTF8String],   -1, SQLITE_TRANSIENT);
        sqlite3_bind_double(stmt, 4, now);

        BOOL ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }
}

- (void)dealloc {
    if (database) sqlite3_close(database);
    [super dealloc];
}

@end