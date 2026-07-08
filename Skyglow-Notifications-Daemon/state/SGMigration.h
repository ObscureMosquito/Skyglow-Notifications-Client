#ifndef SKYGLOW_SG_MIGRATION_H
#define SKYGLOW_SG_MIGRATION_H

#import <Foundation/Foundation.h>

/**
 * Runs one-shot migrations from published pre-profile/pre-keychain builds.
 *
 * Migration intentionally lives in this quarantine file so legacy plist keys,
 * plaintext PEM handling, and old SQLite schemas do not leak back into the
 * normal storage model.
 */
BOOL SGMigrationRunIfNeeded(void);

#endif
