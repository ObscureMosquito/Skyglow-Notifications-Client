#ifndef SKYGLOW_SG_DATABASE_SCHEMA_H
#define SKYGLOW_SG_DATABASE_SCHEMA_H

#include <sqlite3.h>
#include <stdio.h>
#include <stdbool.h>

#define SG_DATABASE_APPLICATION_ID 0x53474E44
#define SG_SCHEMA_VERSION 1

static const char *const kSGDatabaseSchemaSQL =
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
    " PRIMARY KEY(profile_id, msg_id));";

static inline void SGDatabaseSchemaIdentitySQL(char *buf, size_t len) {
    snprintf(buf, len, "PRAGMA application_id = %d; PRAGMA user_version = %d;",
             (int)SG_DATABASE_APPLICATION_ID, SG_SCHEMA_VERSION);
}

static inline bool SGDatabaseReadIntPragma(sqlite3 *db, const char *sql,
                                           int *outValue) {
    if (!db || !sql || !outValue) return false;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return false;
    bool ok = (sqlite3_step(stmt) == SQLITE_ROW);
    if (ok) *outValue = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return ok;
}

#endif
