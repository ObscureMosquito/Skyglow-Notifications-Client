#import "DBManager.h"

@implementation DBManager

+ (DBManager *)sharedStorage {
    static DBManager *shared = nil;
    @synchronized(self) {
        if (shared == nil) {
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
        
        if (sqlite3_open([dbPath UTF8String], &database) != SQLITE_OK) {
            NSLog(@"Failed to open database");
            [self release];
            return nil;
        }
        
        char *errorMsg;
        const char *sql = "CREATE TABLE IF NOT EXISTS notifications (routing_key BLOB PRIMARY KEY, e2ee_key BLOB, bundle_id TEXT, token BLOB)";
        if (sqlite3_exec(database, sql, NULL, NULL, &errorMsg) != SQLITE_OK) {
            NSLog(@"Error creating table: %s", errorMsg);
            sqlite3_free(errorMsg);
        }
    }
    return self;
}

- (BOOL)storeTokenData:(NSData *)routingKey e2eeKey:(NSData *)e2eeKey bundleID:(NSString *)bundleID token:(NSData *)token {
    const char *sql = "INSERT OR REPLACE INTO notifications VALUES (?, ?, ?, ?)";
    sqlite3_stmt *stmt;
    
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, NULL) != SQLITE_OK) {
        NSLog(@"Error preparing statement: %s", sqlite3_errmsg(database));
        return NO;
    }
    
    sqlite3_bind_blob(stmt, 1, [routingKey bytes], [routingKey length], SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, [e2eeKey bytes], [e2eeKey length], SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, [bundleID UTF8String], -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 4, [token bytes], [token length], SQLITE_TRANSIENT);
    
    BOOL success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    
    return success;
}

- (NSDictionary *)dataForRoutingKey:(NSData *)routingKey {
    const char *sql = "SELECT routing_key, e2ee_key, bundle_id FROM notifications WHERE routing_key = ?";
    sqlite3_stmt *stmt;
    NSDictionary *result = nil;
    
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, [routingKey bytes], [routingKey length], SQLITE_TRANSIENT);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            // Get routing key
            const void *routingKeyBytes = sqlite3_column_blob(stmt, 0);
            int routingKeyLength = sqlite3_column_bytes(stmt, 0);
            NSData *retrievedRoutingKey = [NSData dataWithBytes:routingKeyBytes length:routingKeyLength];
            
            // Get E2EE key
            const void *e2eeKeyBytes = sqlite3_column_blob(stmt, 1);
            int e2eeKeyLength = sqlite3_column_bytes(stmt, 1);
            NSData *e2eeKey = [NSData dataWithBytes:e2eeKeyBytes length:e2eeKeyLength];
            
            // Get bundle ID
            const char *bundleIDChars = (const char *)sqlite3_column_text(stmt, 2);
            NSString *bundleID = bundleIDChars ? [NSString stringWithUTF8String:bundleIDChars] : nil;
            
            result = @{
                @"routingKey": retrievedRoutingKey,
                @"e2eeKey": e2eeKey,
                @"bundleID": bundleID ?: [NSNull null]
            };
        }
        sqlite3_finalize(stmt);
    }
    
    return result;
}

- (NSArray *)dataForBundleID:(NSString *)bundleID {
    const char *sql = "SELECT routing_key, e2ee_key, bundle_id, token FROM notifications WHERE bundle_id = ?";
    sqlite3_stmt *stmt;
    NSMutableArray *results = [NSMutableArray array];
    
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, [bundleID UTF8String], -1, SQLITE_TRANSIENT);
        
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            // Get routing key
            const void *routingKeyBytes = sqlite3_column_blob(stmt, 0);
            int routingKeyLength = sqlite3_column_bytes(stmt, 0);
            NSData *routingKey = [NSData dataWithBytes:routingKeyBytes length:routingKeyLength];
            
            // Get E2EE key
            const void *e2eeKeyBytes = sqlite3_column_blob(stmt, 1);
            int e2eeKeyLength = sqlite3_column_bytes(stmt, 1);
            NSData *e2eeKey = [NSData dataWithBytes:e2eeKeyBytes length:e2eeKeyLength];
            
            // Get bundle ID
            const char *bundleIDChars = (const char *)sqlite3_column_text(stmt, 2);
            NSString *retrievedBundleID = bundleIDChars ? [NSString stringWithUTF8String:bundleIDChars] : nil;

            // Get token
            const void *tokenBytes = sqlite3_column_blob(stmt, 3);
            int tokenLength = sqlite3_column_bytes(stmt, 3);
            NSData *token = [NSData dataWithBytes:tokenBytes length:tokenLength];
            
            NSDictionary *result = @{
                @"routingKey": routingKey,
                @"e2eeKey": e2eeKey,
                @"bundleID": retrievedBundleID ?: [NSNull null],
                @"token": token
            };
            
            [results addObject:result];
        }
        sqlite3_finalize(stmt);
    }
    
    return results;
}

- (void)dealloc {
    if (database) sqlite3_close(database);
    [super dealloc];
}

@end