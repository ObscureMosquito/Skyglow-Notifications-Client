#import <Foundation/Foundation.h>

/**
 * SNChannelGateway — the prefs bundle's facade over SGControlChannel.
 *
 * The bundle is loaded into Settings.app and torn down with it.  Two
 * persistent client channels live for the bundle's lifetime: one to the
 * daemon (config reload, debug injection), one to the SpringBoard tweak
 * (register/unregister an input app).  Lookup is lazy; the first call to
 * any post method allocates the relevant channel and kicks its connect
 * loop.  All operations are fire-and-forget — the UI does not wait for
 * an acknowledgement, mirroring the previous Darwin-notification semantics
 * they replace.
 */
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
 * Asks the SpringBoard tweak to remove the given bundle id from the
 * Skyglow-handled list.  Replaces the com.skyglow.sgn.unregisterInputApp
 * Darwin signal plus the lastUnregisteredApp prefs-plist write.
 */
+ (void)postUnregisterInputAppForBundleId:(NSString *)bundleId;

@end
