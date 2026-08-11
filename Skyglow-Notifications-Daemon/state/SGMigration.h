#ifndef SKYGLOW_SG_MIGRATION_H
#define SKYGLOW_SG_MIGRATION_H

#import <Foundation/Foundation.h>

/** Runs one-shot migrations from pre-profile/pre-keychain builds. */
BOOL SGMigrationRunIfNeeded(void);

#endif
