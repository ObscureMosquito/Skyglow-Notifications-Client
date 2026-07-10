#import <Foundation/Foundation.h>
#import "SGSharedConstants.h"

/* Rootless-aware absolute path */
NSString *SGNPath(NSString *path);

#define kPrefsPlistPath SGNPath(SG_PREFS_PLIST_PATH)

/* Reads an instance variable by name, or nil if the object/ivar is absent. */
id GetIvar(id obj, const char *name);

/* Resolves an installed application object from a bundle id, verifying the
 * reported identity matches. nil if not installed. */
id SBApp_LookupByIdentifier(NSString *bundleId);

/* Runtime app-intent overlay */
void SGNSetRuntimeAppIntent(NSString *bundleId, BOOL usesSkyglow);
void SGNClearRuntimeAppIntent(NSString *bundleId);
id   SGNEffectiveAppIntent(NSString *bundleId);
