#import <Foundation/Foundation.h>
#import "SGStatusServer.h"

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
 * Asks the daemon to acknowledge and then shut down cleanly.  launchd's
 * KeepAlive policy starts a replacement; no privileged Settings helper is
 * involved.  Completion fires on the main queue after the acknowledgement.
 */
+ (void)restartDaemonWithCompletion:(SNChannelCommandCompletion)completion;

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

/* Same as postRegisterInputAppForBundleId: but waits for the SpringBoard
 * tweak to acknowledge.  Completion fires on the main queue with ok=YES
 * on ack, or ok=NO if SB didn't respond.  Used by debug tooling where
 * silent fire-and-forget hides real failures. */
+ (void)registerInputAppForBundleId:(NSString *)bundleId
                         completion:(SNChannelCommandCompletion)completion;

/**
 * Enable/disable a single app through the daemon and wait for its ack.  The
 * daemon syncs its DB + server filter AND now owns the plist appStatus write,
 * so the UI must not touch the plist itself — it reflects the change only when
 * ok=YES.  Completion fires on the main queue; on ok=NO the caller should
 * revert the toggle and surface `message`.
 */
+ (void)enableAppForBundleId:(NSString *)bundleId completion:(SNChannelCommandCompletion)completion;
+ (void)disableAppForBundleId:(NSString *)bundleId completion:(SNChannelCommandCompletion)completion;

+ (void)deleteAppForBundleId:(NSString *)bundleId completion:(SNChannelCommandCompletion)completion;

/**
 * Flips the global enabled switch through the daemon (which owns the plist
 * write + config reload).  Replaces the prefs bundle writing `enabled` to the
 * plist and posting a separate reload.  Completion fires on the main queue.
 */
+ (void)setEnabled:(BOOL)enabled completion:(SNChannelCommandCompletion)completion;

/**
 * Atomically deletes the profile at the given index (1..5) via the daemon.
 * The daemon does keychain + plist + DB cleanup in one step.  Completion
 * fires on the main queue with ok=YES on full success, or ok=NO with a
 * user-facing message on any failure.  UI MUST NOT remove the profile
 * row optimistically, only on ok=YES.
 */
+ (void)deleteProfileAtIndex:(NSInteger)profileIndex completion:(SNChannelCommandCompletion)completion;

/**
 * Switches the active profile via the daemon.  The daemon writes the
 * activeProfile key, reloads, and triggers an immediate reconnect to the
 * new server.  Completion fires on the main queue.
 */
+ (void)setActiveProfileAtIndex:(NSInteger)profileIndex completion:(SNChannelCommandCompletion)completion;

/**
 * Creates or edits a profile through the daemon.  Pass a PEM string for
 * creation/certificate replacement; pass nil for address-only edits that
 * preserve the existing certificate.  Completion fires on the main queue.
 */
+ (void)saveProfileAtIndex:(NSInteger)profileIndex
             serverAddress:(NSString *)serverAddress
            certificatePEM:(NSString *)certificatePEM
                completion:(SNChannelCommandCompletion)completion;

/**
 * Stores or removes (nil) a profile's registration identity — the
 * operator-issued client cert + key PEM required by servers that gate
 * first-time registration.  Completion fires on the main queue.
 */
+ (void)setRegistrationIdentityAtIndex:(NSInteger)profileIndex
                           identityPEM:(NSString *)identityPEM
                            completion:(SNChannelCommandCompletion)completion;

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
