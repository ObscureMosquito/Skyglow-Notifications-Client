#import <Foundation/Foundation.h>
#import "../Skyglow-Notifications-Daemon/SGStatusServer.h"

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
typedef void (^SNChannelBundleListCompletion)(BOOL ok, NSArray *bundleIds, NSString *message);

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
 * Atomically deletes the profile at the given index (1..5) via the daemon.
 * The daemon does keychain + plist + DB cleanup in one step.  Completion
 * fires on the main queue with ok=YES on full success, or ok=NO with a
 * user-facing message on any failure.  UI MUST NOT remove the profile
 * row optimistically, only on ok=YES.
 */
+ (void)deleteProfileAtIndex:(NSInteger)profileIndex completion:(SNChannelCommandCompletion)completion;

/**
 * Asynchronously requests the list of bundles iOS considers push-registered
 * (third-party only).  The SB tweak handler returns the iOS-native push
 * registration table (apsd-style — apps that have been registered for push
 * regardless of provider).  Used by the prefs app list to render the
 * "Apple Push" section after subtracting bundles already in our own
 * Skyglow plist.
 *
 * Completion fires on the main queue with either the array of NSString
 * bundle IDs or a user-facing error if the SB tweak is unreachable.
 */
+ (void)queryNativelyPushRegisteredBundlesWithCompletion:(SNChannelBundleListCompletion)completion;

/**
 * Subscribes to daemon status updates published over the existing control
 * channel.  Handler fires on each SGCEVT_STATE_CHANGED event the daemon
 * publishes (i.e. every state transition).  Automatically re-subscribes when
 * the channel reconnects (e.g. after daemon restart), so the caller doesn't
 * need to think about lifecycle.  Handler runs on an arbitrary queue — hop
 * to main for UI work.
 *
 * Only one subscriber is intended; subsequent calls replace the previous
 * handler.
 */
+ (void)subscribeToStatusUpdatesWithHandler:(void (^)(SGStatusPayload payload))handler;

/**
 * One-shot request for the daemon's current status snapshot.  Handler runs
 * on the main queue.  On failure (timeout / unreachable), payload is a
 * zeroed struct with state == SGStateDisabled.
 */
+ (void)queryStatusWithCompletion:(void (^)(SGStatusPayload payload))completion;

@end
