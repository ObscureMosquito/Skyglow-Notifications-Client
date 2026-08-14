#import "SGMigration.h"
#import "SGControlChannelProtocol.h"
#import "SGAtomicFile.h"
#import "SGConfiguration.h"
#import "SGDatabaseSchema.h"
#import "SGKeychainStore.h"
#import "SGLog.h"

#include <errno.h>
#include <sqlite3.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <TargetConditionals.h>

#define SG_MIGRATION_VERSION 2

static NSString * const kSGMigrationVersionKey = @"storageMigrationVersion";
#if TARGET_OS_IPHONE
static NSString * const kSGKeychainAccessibilityMigrationKey = @"keychainAccessibilityMigrationVersion";
#endif
static NSString * const kSGLegacyPrivateKeyPath = @"/var/Library/PreferenceBundles/SGNPreferenceBundle.bundle/com.skyglow.client.pem";
static BOOL SGMStringHasText(id value) {
    return [value isKindOfClass:[NSString class]] &&
           [(NSString *)value length] > 0;
}

static BOOL SGMPemLooksLikePrivateKey(NSString *pem) {
    return [pem rangeOfString:@"-----BEGIN RSA PRIVATE KEY-----"].location != NSNotFound ||
           [pem rangeOfString:@"-----BEGIN PRIVATE KEY-----"].location != NSNotFound;
}

static NSString *SGMResolvedLegacyPath(NSString *rawPath) {
    if (!SGMStringHasText(rawPath)) return nil;
    if ([rawPath length] > 1024) return nil;
    if ([rawPath characterAtIndex:0] != '/') return nil;
    return SGPath(rawPath);
}

static NSString *SGMReadSmallUTF8File(NSString *path) {
    NSData *data = SGAtomicReadData(path, SG_STORAGE_SMALL_FILE_MAX_BYTES);
    if (!data) return nil;
    return [[[NSString alloc] initWithData:data
                                  encoding:NSUTF8StringEncoding] autorelease];
}

static NSString *SGMReadLegacyPEMValue(id rawValue) {
    if (!SGMStringHasText(rawValue)) return nil;

    NSString *value = (NSString *)rawValue;
    if ([value rangeOfString:@"-----BEGIN"].location != NSNotFound) {
        return value;
    }

    NSString *path = SGMResolvedLegacyPath(value);
    if (!path) return nil;
    return SGMReadSmallUTF8File(path);
}

static void SGMRemoveKnownLegacyPrivateKeyFile(id rawValue) {
    if (!SGMStringHasText(rawValue)) return;

    NSString *legacyPath = (NSString *)rawValue;
    if (![legacyPath isEqualToString:kSGLegacyPrivateKeyPath]) return;

    NSString *diskPath = SGPath(legacyPath);
    (void)SGDurableRemoveItem(diskPath, NULL);
}

static id SGMFirstTextValue(NSDictionary *primary,
                            NSDictionary *secondary,
                            NSArray *keys) {
    for (NSString *key in keys) {
        id value = [primary objectForKey:key];
        if (SGMStringHasText(value)) return value;
    }
    for (NSString *key in keys) {
        id value = [secondary objectForKey:key];
        if (SGMStringHasText(value)) return value;
    }
    return nil;
}

static BOOL SGMProfileAlreadyLooksMigrated(NSDictionary *profile) {
    if (![profile isKindOfClass:[NSDictionary class]]) return NO;
    if ([profile objectForKey:@"privateKey"]) return NO;

    NSString *serverPubKey = [profile objectForKey:@"server_pub_key"];
    return [serverPubKey isEqualToString:SGProfileCertificatePathForIndex(1)];
}

static BOOL SGMWriteMainPreferences(NSDictionary *mainPrefs,
                                    NSString *legacyServerAddress) {
    NSString *mainPath = SGPath(SG_PREFS_PLIST_PATH);
    NSMutableDictionary *outPrefs =
        [NSMutableDictionary dictionaryWithDictionary:mainPrefs ?: @{}];

    [outPrefs setObject:[NSNumber numberWithInteger:1]
                 forKey:@"activeProfile"];
    [outPrefs setObject:[NSNumber numberWithInteger:SG_MIGRATION_VERSION]
                 forKey:kSGMigrationVersionKey];
    if ([legacyServerAddress length] > 0) {
        /* Harmless default for older settings panes; active runtime is profile1. */
        [outPrefs setObject:legacyServerAddress
                     forKey:@"notificationServerAddress"];
    }

    NSArray *legacyKeys = [NSArray arrayWithObjects:
        @"server_address", @"device_address", @"privateKey", @"publicKey",
        @"server_pub_key", nil];
    for (NSString *key in legacyKeys) [outPrefs removeObjectForKey:key];

    return SGAtomicWritePropertyList(outPrefs, mainPath, 0644, NULL);
}

static BOOL SGMigrateLegacyProfileIfNeeded(void) {
    NSString *mainPath = SGPath(SG_PREFS_PLIST_PATH);
    NSString *profilePath = SGProfilePlistPathForIndex(1);

    NSDictionary *mainPrefs =
        [NSDictionary dictionaryWithContentsOfFile:mainPath] ?: @{};
    NSDictionary *profilePrefs =
        [NSDictionary dictionaryWithContentsOfFile:profilePath] ?: @{};

    NSNumber *migrationVersion = [mainPrefs objectForKey:kSGMigrationVersionKey];
    if (SGMProfileAlreadyLooksMigrated(profilePrefs)) {
        if ([migrationVersion integerValue] < SG_MIGRATION_VERSION) {
            NSString *serverAddress =
                SGMStringHasText([profilePrefs objectForKey:@"server_address"])
                    ? [profilePrefs objectForKey:@"server_address"] : nil;
            return SGMWriteMainPreferences(mainPrefs, serverAddress);
        }
        return YES;
    }

    id serverAddressValue = SGMFirstTextValue(
        profilePrefs, mainPrefs,
        [NSArray arrayWithObjects:
            @"server_address", @"notificationServerAddress", nil]);
    NSString *serverAddress = SGMStringHasText(serverAddressValue)
        ? (NSString *)serverAddressValue : nil;

    id serverCertValue = SGMFirstTextValue(
        profilePrefs, mainPrefs,
        [NSArray arrayWithObjects:@"server_pub_key", nil]);
    NSString *serverCertPEM = SGMReadLegacyPEMValue(serverCertValue);

    id deviceAddressValue = SGMFirstTextValue(
        profilePrefs, mainPrefs,
        [NSArray arrayWithObjects:@"device_address", nil]);
    NSString *deviceAddress = SGMStringHasText(deviceAddressValue)
        ? (NSString *)deviceAddressValue : nil;

    id privateKeyValue = SGMFirstTextValue(
        profilePrefs, mainPrefs,
        [NSArray arrayWithObjects:@"privateKey", nil]);
    NSString *privateKeyPEM = SGMReadLegacyPEMValue(privateKeyValue);

    BOOL hasLegacyProfileMaterial =
        [serverAddress length] > 0 || [serverCertPEM length] > 0 ||
        [deviceAddress length] > 0 || [privateKeyPEM length] > 0 ||
        [profilePrefs objectForKey:@"privateKey"] ||
        [mainPrefs objectForKey:@"privateKey"];
    if (!hasLegacyProfileMaterial) return YES;

    if (![serverAddress length] || !SG_LooksLikePEMCertificate(serverCertPEM)) {
        SGLOGW(SGMigration,
               "code=SGN_MIGRATION_PROFILE_DEFERRED result=deferred reason=incomplete_profile");
        return YES;
    }

    BOOL shouldCarryRegistration =
        ([deviceAddress length] > 0 && SGMPemLooksLikePrivateKey(privateKeyPEM));
    if ([deviceAddress length] > 0 && !shouldCarryRegistration) {
        SGLOGW(SGMigration,
               "code=SGN_MIGRATION_PROFILE_DROPPED_CREDENTIALS result=continue reason=missing_private_key");
    }

    if (shouldCarryRegistration &&
        !SGKeychain_StorePrivateKeyPEM(privateKeyPEM, 1)) {
        /* Legacy plist may hold the only key copy; leave it for retry on next launch. */
        SGLOGW(SGMigration,
               "code=SGN_MIGRATION_KEYCHAIN_DEFERRED result=deferred profile=1");
        return YES;
    }

    SGEnsureRuntimeDirectories();

    NSString *storedCertPath = SGProfileCertificatePathForIndex(1);
    NSString *certDiskPath = SGPath(storedCertPath);
    NSData *certData = [serverCertPEM dataUsingEncoding:NSUTF8StringEncoding];
    if (!certData || !SGAtomicWriteData(certData, certDiskPath, 0644, NULL)) {
        SGLOGE(SGMigration,
               "code=SGN_MIGRATION_PROFILE_FAILED result=failed reason=certificate_write");
        if (shouldCarryRegistration) SGKeychain_DeletePrivateKey(1);
        return NO;
    }

    NSMutableDictionary *newProfile = [NSMutableDictionary dictionary];
    [newProfile setObject:serverAddress forKey:@"server_address"];
    [newProfile setObject:storedCertPath forKey:@"server_pub_key"];
    if (shouldCarryRegistration) {
        [newProfile setObject:deviceAddress forKey:@"device_address"];
    }

    if (!SGAtomicWritePropertyList(newProfile, profilePath, 0644, NULL)) {
        SGLOGE(SGMigration,
               "code=SGN_MIGRATION_PROFILE_FAILED result=failed reason=profile_write");
        if (shouldCarryRegistration) SGKeychain_DeletePrivateKey(1);
        return NO;
    }

    if (!SGMWriteMainPreferences(mainPrefs, serverAddress)) {
        SGLOGE(SGMigration,
               "code=SGN_MIGRATION_PROFILE_FAILED result=failed reason=main_prefs_write");
        return NO;
    }

    if (shouldCarryRegistration) {
        SGMRemoveKnownLegacyPrivateKeyFile(privateKeyValue);
    }

    SGLOGI(SGMigration,
           "code=SGN_MIGRATION_PROFILE_APPLIED profile=1 registered=%d",
           shouldCarryRegistration ? 1 : 0);
    return YES;
}

static BOOL SGMigrateKeychainAccessibilityIfNeeded(void) {
#if !TARGET_OS_IPHONE
    return YES;
#else
    NSString *mainPath = SGPath(SG_PREFS_PLIST_PATH);
    NSDictionary *mainPrefs = [NSDictionary dictionaryWithContentsOfFile:mainPath] ?: @{};
    
    if ([[mainPrefs objectForKey:kSGKeychainAccessibilityMigrationKey]
            integerValue] >= 1) {
        return YES;
    }

    for (NSInteger profileIdx = 1; profileIdx <= SG_PROFILE_INDEX_MAX; profileIdx++) {
        BOOL found = NO;
        if (!SGKeychain_RewrapPrivateKeyForPreUnlockAccess(profileIdx,
                                                            &found)) {
            SGLOGW(SGMigration,
                   "code=SGN_MIGRATION_KEYCHAIN_ACCESSIBILITY_DEFERRED result=deferred profile=%ld",
                   (long)profileIdx);
            return NO;
        }
        if (found) {
            SGLOGI(SGMigration,
                   "code=SGN_MIGRATION_KEYCHAIN_ACCESSIBILITY_REWRAPPED profile=%ld",
                   (long)profileIdx);
        }
    }

    NSMutableDictionary *updatedPrefs =
        [NSMutableDictionary dictionaryWithDictionary:mainPrefs];
    [updatedPrefs setObject:[NSNumber numberWithInteger:1]
                     forKey:kSGKeychainAccessibilityMigrationKey];
    if (!SGAtomicWritePropertyList(updatedPrefs, mainPath, 0644, NULL)) {
        SGLOGE(SGMigration,
               "code=SGN_MIGRATION_KEYCHAIN_ACCESSIBILITY_FAILED result=failed reason=stamp");
        return NO;
    }

    return YES;
#endif
}

static BOOL SGMSQLiteTableExists(sqlite3 *db, const char *tableName) {
    sqlite3_stmt *stmt = NULL;
    BOOL exists = NO;
    const char *sql =
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, tableName, -1, SQLITE_STATIC);
        exists = (sqlite3_step(stmt) == SQLITE_ROW);
    }
    if (stmt) sqlite3_finalize(stmt);
    return exists;
}

static BOOL SGMSQLiteTableHasColumn(sqlite3 *db,
                                    const char *tableName,
                                    const char *columnName) {
    char sql[128];
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", tableName);

    sqlite3_stmt *stmt = NULL;
    BOOL found = NO;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *name = (const char *)sqlite3_column_text(stmt, 1);
            if (name && strcmp(name, columnName) == 0) {
                found = YES;
                break;
            }
        }
    }
    if (stmt) sqlite3_finalize(stmt);
    return found;
}

static BOOL SGMSQLiteExec(sqlite3 *db, const char *sql, const char *reason) {
    char *error = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &error) == SQLITE_OK) return YES;

    SGLOGE(SGMigration,
           "code=SGN_MIGRATION_DATABASE_FAILED result=failed reason=%s sqlite=%s",
           reason ? reason : "exec", error ? error : "(unknown)");
    sqlite3_free(error);
    return NO;
}

static BOOL SGMSQLiteRenameIfExists(sqlite3 *db,
                                    const char *table,
                                    const char *legacyTable) {
    if (!SGMSQLiteTableExists(db, table)) return YES;

    char sql[160];
    snprintf(sql, sizeof(sql), "ALTER TABLE %s RENAME TO %s",
             table, legacyTable);
    return SGMSQLiteExec(db, sql, "rename_legacy_table");
}

static BOOL SGMSQLiteDropIfExists(sqlite3 *db, const char *table) {
    char sql[160];
    snprintf(sql, sizeof(sql), "DROP TABLE IF EXISTS %s", table);
    return SGMSQLiteExec(db, sql, "drop_legacy_table");
}

static BOOL SGMigrateLegacyDatabaseIfNeeded(void) {
    NSString *dbPath = SGPath(SG_DB_PATH);
    if (![[NSFileManager defaultManager] fileExistsAtPath:dbPath]) return YES;

    sqlite3 *db = NULL;
    if (sqlite3_open([dbPath fileSystemRepresentation], &db) != SQLITE_OK) {
        SGLOGE(SGMigration,
               "code=SGN_MIGRATION_DATABASE_FAILED result=failed reason=open");
        if (db) sqlite3_close(db);
        return NO;
    }
    sqlite3_busy_timeout(db, 3000);

    BOOL ok = YES;
    int applicationID = 0;
    int schemaVersion = 0;
    if (!SGDatabaseReadIntPragma(db, "PRAGMA application_id", &applicationID) ||
        !SGDatabaseReadIntPragma(db, "PRAGMA user_version", &schemaVersion)) {
        SGLOGE(SGMigration,
               "code=SGN_MIGRATION_DATABASE_FAILED result=failed reason=version_probe");
        sqlite3_close(db);
        return NO;
    }

    if (applicationID == SG_DATABASE_APPLICATION_ID &&
        schemaVersion == SG_SCHEMA_VERSION) {
        sqlite3_close(db);
        return YES;
    }

    BOOL hasNotifications = SGMSQLiteTableExists(db, "notifications");
    BOOL hasProfileColumn =
        hasNotifications &&
        SGMSQLiteTableHasColumn(db, "notifications", "profile_id");

    if (!hasNotifications) {
        sqlite3_close(db);
        return YES;
    }

    if (applicationID != 0 || hasProfileColumn) {
        SGLOGE(SGMigration,
               "code=SGN_MIGRATION_DATABASE_FAILED result=failed reason=unsupported_schema app_id=%d version=%d profile_column=%d",
               applicationID, schemaVersion, hasProfileColumn ? 1 : 0);
        sqlite3_close(db);
        return NO;
    }

    SGLOGI(SGMigration,
           "code=SGN_MIGRATION_DATABASE_START profile=1 from_version=%d",
           schemaVersion);

    ok = SGMSQLiteExec(db, "BEGIN IMMEDIATE", "begin");
    ok = ok && SGMSQLiteRenameIfExists(db, "notifications",
                                       "notifications_legacy_migration");
    ok = ok && SGMSQLiteRenameIfExists(db, "dns_cache",
                                       "dns_cache_legacy_migration");
    ok = ok && SGMSQLiteRenameIfExists(db, "pending_acks",
                                       "pending_acks_legacy_migration");
    ok = ok && SGMSQLiteRenameIfExists(db, "settings",
                                       "settings_legacy_migration");
    ok = ok && SGMSQLiteRenameIfExists(db, "seen_messages",
                                       "seen_messages_legacy_migration");
    ok = ok && SGMSQLiteRenameIfExists(db, "local_pending_deliveries",
                                       "local_pending_deliveries_legacy_migration");
    ok = ok && SGMSQLiteExec(db, kSGDatabaseSchemaSQL, "create_schema");
    ok = ok && SGMSQLiteExec(db,
        "INSERT OR REPLACE INTO notifications "
        "(profile_id, routing_key, e2ee_key, bundle_id, token, is_muted) "
        "SELECT 1, routing_key, e2ee_key, bundle_id, token, 0 "
        "FROM notifications_legacy_migration",
        "copy_notifications");

    if (ok && SGMSQLiteTableExists(db, "dns_cache_legacy_migration")) {
        ok = SGMSQLiteExec(db,
            "INSERT OR REPLACE INTO dns_cache "
            "(profile_id, domain, ip, port, updated_at) "
            "SELECT 1, domain, ip, port, updated_at "
            "FROM dns_cache_legacy_migration",
            "copy_dns_cache");
    }
    if (ok && SGMSQLiteTableExists(db, "pending_acks_legacy_migration")) {
        ok = SGMSQLiteExec(db,
            "INSERT OR REPLACE INTO pending_acks "
            "(profile_id, msg_id, status) "
            "SELECT 1, msg_id, status "
            "FROM pending_acks_legacy_migration",
            "copy_pending_acks");
    }
    if (ok && SGMSQLiteTableExists(db, "settings_legacy_migration")) {
        ok = SGMSQLiteExec(db,
            "INSERT OR REPLACE INTO settings "
            "(profile_id, key, value) "
            "SELECT 1, key, value "
            "FROM settings_legacy_migration",
            "copy_settings");
    }
    if (ok && SGMSQLiteTableExists(db, "seen_messages_legacy_migration")) {
        ok = SGMSQLiteExec(db,
            "INSERT OR REPLACE INTO seen_messages "
            "(profile_id, msg_id, expires_at) "
            "SELECT 1, msg_id, expires_at "
            "FROM seen_messages_legacy_migration",
            "copy_seen_messages");
    }
    if (ok && SGMSQLiteTableExists(db, "local_pending_deliveries_legacy_migration")) {
        ok = SGMSQLiteExec(db,
            "INSERT OR REPLACE INTO local_pending_deliveries "
            "(profile_id, msg_id, bundle_id, payload, device_seq, expires_at) "
            "SELECT 1, msg_id, bundle_id, payload, device_seq, expires_at "
            "FROM local_pending_deliveries_legacy_migration",
            "copy_local_pending_deliveries");
    }

    ok = ok && SGMSQLiteDropIfExists(db, "notifications_legacy_migration");
    ok = ok && SGMSQLiteDropIfExists(db, "dns_cache_legacy_migration");
    ok = ok && SGMSQLiteDropIfExists(db, "pending_acks_legacy_migration");
    ok = ok && SGMSQLiteDropIfExists(db, "settings_legacy_migration");
    ok = ok && SGMSQLiteDropIfExists(db, "seen_messages_legacy_migration");
    ok = ok && SGMSQLiteDropIfExists(db, "local_pending_deliveries_legacy_migration");
    char identitySQL[96];
    SGDatabaseSchemaIdentitySQL(identitySQL, sizeof(identitySQL));
    ok = ok && SGMSQLiteExec(db, identitySQL, "stamp_schema");

    if (ok && sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        SGLOGE(SGMigration,
               "code=SGN_MIGRATION_DATABASE_FAILED result=failed reason=commit sqlite=%s",
               sqlite3_errmsg(db));
        ok = NO;
    }
    if (!ok) sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);

    sqlite3_close(db);
    if (!ok) return NO;

    chmod([dbPath fileSystemRepresentation], 0600);
    SGLOGI(SGMigration,
           "code=SGN_MIGRATION_DATABASE_APPLIED profile=1");
    return YES;
}

BOOL SGMigrationRunIfNeeded(void) {
    BOOL profileOK = SGMigrateLegacyProfileIfNeeded();
    BOOL keychainOK = profileOK && SGMigrateKeychainAccessibilityIfNeeded();
    BOOL databaseOK = SGMigrateLegacyDatabaseIfNeeded();
    return profileOK && keychainOK && databaseOK;
}
