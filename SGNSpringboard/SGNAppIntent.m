#import "SGNAppIntent.h"
#import "SGNPrivateAPI.h"
#import <objc/runtime.h>

NSString *SGNPath(NSString *path) {
    static int rootless = -1;
    if (rootless < 0) {
        rootless = [[NSFileManager defaultManager]
            fileExistsAtPath:@"/var/jb"] ? 1 : 0;
    }
    return rootless ? [@"/var/jb" stringByAppendingString:path] : path;
}

id GetIvar(id obj, const char *name) {
    if (!obj || !name) return nil;
    Ivar iv = class_getInstanceVariable(object_getClass(obj), name);
    return iv ? object_getIvar(obj, iv) : nil;
}

id SBApp_LookupByIdentifier(NSString *bundleId) {
    SBApplicationController *ctrl = [objc_getClass("SBApplicationController") sharedInstance];
    id app = nil;
    if ([ctrl respondsToSelector:@selector(applicationWithBundleIdentifier:)]) {
        app = [ctrl applicationWithBundleIdentifier:bundleId];
    } else {
        app = [ctrl applicationWithDisplayIdentifier:bundleId];
    }
    if (!app) return nil;

    NSString *reportedId = nil;
    if ([app respondsToSelector:@selector(bundleIdentifier)]) {
        reportedId = [app performSelector:@selector(bundleIdentifier)];
    } else if ([app respondsToSelector:@selector(displayIdentifier)]) {
        reportedId = [app performSelector:@selector(displayIdentifier)];
    }
    if (!reportedId.length) return nil;
    if (![reportedId isEqualToString:bundleId]) return nil;
    return app;
}

#pragma mark - Runtime App Intent

static NSMutableDictionary *gSGNRuntimeAppIntent = nil;

static NSObject *SGNRuntimeIntentLock(void) {
    static NSObject *lock = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        lock = [[NSObject alloc] init];
    });
    return lock;
}

void SGNSetRuntimeAppIntent(NSString *bundleId, BOOL usesSkyglow) {
    if (!bundleId.length) return;
    @synchronized(SGNRuntimeIntentLock()) {
        if (!gSGNRuntimeAppIntent) {
            gSGNRuntimeAppIntent = [[NSMutableDictionary alloc] init];
        }
        [gSGNRuntimeAppIntent setObject:(usesSkyglow ? (id)@YES : (id)[NSNull null])
                                forKey:bundleId];
    }
}

void SGNClearRuntimeAppIntent(NSString *bundleId) {
    if (!bundleId.length) return;
    @synchronized(SGNRuntimeIntentLock()) {
        [gSGNRuntimeAppIntent removeObjectForKey:bundleId];
    }
}

id SGNEffectiveAppIntent(NSString *bundleId) {
    if (!bundleId.length) return nil;
    NSDictionary *prefs =
        [NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath];
    id persisted = [[prefs objectForKey:@"appStatus"] objectForKey:bundleId];

    id runtime = nil;
    @synchronized(SGNRuntimeIntentLock()) {
        runtime = [[gSGNRuntimeAppIntent objectForKey:bundleId] retain];
    }
    if (!runtime) return persisted;

    BOOL runtimeUsesSkyglow = (runtime != [NSNull null]);
    BOOL diskMatches = runtimeUsesSkyglow ? (persisted != nil)
                                         : (persisted == nil);
    if (diskMatches) {
        SGNClearRuntimeAppIntent(bundleId);
        [runtime release];
        return persisted;
    }

    if (!runtimeUsesSkyglow) {
        [runtime release];
        return nil;
    }
    return [runtime autorelease];
}
