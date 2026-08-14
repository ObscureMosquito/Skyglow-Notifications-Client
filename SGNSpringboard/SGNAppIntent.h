#import <Foundation/Foundation.h>
#import "SGConfiguration.h"
#import "SGSharedConstants.h"

/** Rootless-aware absolute path. */
NSString *SGNPath(NSString *path);

#define kPrefsPlistPath SGNPath(SG_PREFS_PLIST_PATH)

id GetIvar(id obj, const char *name);

/** Verifies the resolved app's identity matches the requested bundle id. */
id SBApp_LookupByIdentifier(NSString *bundleId);

void SGNSetRuntimeAppIntent(NSString *bundleId, BOOL usesSkyglow);
void SGNClearRuntimeAppIntent(NSString *bundleId);
id   SGNEffectiveAppIntent(NSString *bundleId);
