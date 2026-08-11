#import <Foundation/Foundation.h>
#import "SGStatusServer.h"

typedef void (^SNChannelCommandCompletion)(BOOL ok, NSString *message);
typedef void (^SNChannelBundleListCompletion)(BOOL ok, NSArray *bundleIds, NSString *message);

@interface SNChannelGateway : NSObject

/** Tells the daemon to re-read its configuration plist. */
+ (void)postReloadConfig;

/** Asks the daemon to acknowledge and then shut down cleanly. */
+ (void)restartDaemonWithCompletion:(SNChannelCommandCompletion)completion;

/** Pretty obvious what this does */
+ (void)postTestInject;

/** Asks the appropiate manager to attempt toregister the given bundle id */
+ (void)postRegisterInputAppForBundleId:(NSString *)bundleId;

/** Same as postRegisterInputAppForBundleId: but waits for the manager to acknowledge. */
+ (void)registerInputAppForBundleId:(NSString *)bundleId
                         completion:(SNChannelCommandCompletion)completion;

/** Toggle a single app and wait for its ack */
+ (void)enableAppForBundleId:(NSString *)bundleId completion:(SNChannelCommandCompletion)completion;
+ (void)disableAppForBundleId:(NSString *)bundleId completion:(SNChannelCommandCompletion)completion;

+ (void)deleteAppForBundleId:(NSString *)bundleId completion:(SNChannelCommandCompletion)completion;

/** Toggles the global enabled switch */
+ (void)setEnabled:(BOOL)enabled completion:(SNChannelCommandCompletion)completion;

/** Atomically deletes the profile at the given index */
+ (void)deleteProfileAtIndex:(NSInteger)profileIndex completion:(SNChannelCommandCompletion)completion;

/** Switches the active profile. */
+ (void)setActiveProfileAtIndex:(NSInteger)profileIndex completion:(SNChannelCommandCompletion)completion;

/** Creates or edits a profile. */
+ (void)saveProfileAtIndex:(NSInteger)profileIndex
             serverAddress:(NSString *)serverAddress
            certificatePEM:(NSString *)certificatePEM
                completion:(SNChannelCommandCompletion)completion;

/** Stores or removes a profiles registration identity. */
+ (void)setRegistrationIdentityAtIndex:(NSInteger)profileIndex
                           identityPEM:(NSString *)identityPEM
                            completion:(SNChannelCommandCompletion)completion;

/** Asynchronously requests the list of bundles iOS considers push-registered */
+ (void)queryNativelyPushRegisteredBundlesWithCompletion:(SNChannelBundleListCompletion)completion;

/** Subscribes to daemon status updates published over the existing control channel. */
+ (void)subscribeToStatusUpdatesWithHandler:(void (^)(SGStatusPayload payload))handler;

/** request for the daemon's current status (one time)*/
+ (void)queryStatusWithCompletion:(void (^)(SGStatusPayload payload))completion;

@end
