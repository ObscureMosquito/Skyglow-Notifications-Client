#import <Foundation/Foundation.h>

/**
 * SNChannelGateway — the prefs bundle's facade over SGControlChannel.
 *
 * The bundle is loaded into Settings.app and torn down with it.  Two
 * persistent client channels live for the bundle's lifetime: one to the
 * daemon (config reload, debug injection), one to the SpringBoard tweak
 * (register/unregister an input app).  Lookup is lazy; the first call to
 * any post method allocates the relevant channel and kicks its connect
 * loop.
 */
typedef void (^SNChannelCommandCompletion)(BOOL ok, NSString *message);

@interface SNChannelGateway : NSObject

/**
 * Tells the daemon to re-read its configuration plist.  Replaces the
 * com.skyglow.sgn.reload_config Darwin notification posted from three
 * prefs view controllers when the user toggles a setting.
 */
+ (void)postReloadConfig;

/**
 * Triggers the daemon's debug test-inject hook.  Replaces the
 * com.skyglow.test-inject Darwin signal posted from SNDebugViewController.
 */
+ (void)postTestInject;

/**
 * Asks the SpringBoard tweak to register the given bundle id as a
 * Skyglow-handled app (token request + remote-notification registration).
 * Replaces the com.skyglow.sgn.registerInputApp Darwin signal plus the
 * lastRegisteredApp prefs-plist write that smuggled the bundle id alongside.
 */
+ (void)postRegisterInputAppForBundleId:(NSString *)bundleId;

/**
 * Unified per-app state commands sent to the DAEMON (not the SB tweak).
 * These replace the prior pattern of the prefs bundle writing the DB
 * directly: the plist remains the source-of-truth for user intent and is
 * written here, then the daemon is told to sync its DB + server filter
 * accordingly.  Fire-and-forget; the daemon handles the cascade including
 * any required SB-side actions (e.g. native deregister on delete).
 */
+ (void)postEnableAppForBundleId:(NSString *)bundleId;
+ (void)postDisableAppForBundleId:(NSString *)bundleId;
+ (void)deleteAppForBundleId:(NSString *)bundleId completion:(SNChannelCommandCompletion)completion;

/**
 * Asynchronously requests the list of bundles iOS considers push-registered
 * (third-party only).  The SB tweak handler returns the iOS-native push
 * registration table (apsd-style — apps that have been registered for push
 * regardless of provider).  Used by the prefs app list to render the
 * "Apple Push" section after subtracting bundles already in our own
 * Skyglow plist.
 *
 * Completion fires on the main queue with the array of NSString bundle IDs,
 * or an empty array if the channel is unreachable / SB tweak isn't loaded.
 */
+ (void)queryNativelyPushRegisteredBundlesWithCompletion:(void (^)(NSArray *bundleIds))completion;

@end
