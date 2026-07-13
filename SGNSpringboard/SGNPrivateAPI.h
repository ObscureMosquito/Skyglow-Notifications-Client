#import <Foundation/Foundation.h>

/* Private SpringBoard / ApplePushService / UserNotifications interfaces the
 * tweak talks to
 */

@interface APSIncomingMessage : NSObject
- (instancetype)initWithTopic:(NSString *)topic userInfo:(NSDictionary *)userInfo;
- (void)setTimestamp:(NSDate *)date;
- (NSDictionary *)userInfo;
- (NSString *)correlationIdentifier;
- (void)setCorrelationIdentifier:(NSString *)identifier;
- (NSInteger)priority;
- (void)setPriority:(NSInteger)priority;
- (NSInteger)pushType;
- (void)setPushType:(NSInteger)pushType;
- (NSString *)unc_bundleIdentifier;
@end

@interface UNNotificationRequest : NSObject
+ (instancetype)requestWithIdentifier:(NSString *)identifier
                           pushPayload:(NSDictionary *)payload
                      bundleIdentifier:(NSString *)bundleIdentifier;
- (id)content;
@end

@interface NSObject (SGNUserNotificationContent)
- (BOOL)unc_willNotifyUser;
- (BOOL)unc_willAlertUser;
@end

@interface SBApplicationController : NSObject
+ (instancetype)sharedInstance;
- (id)applicationWithDisplayIdentifier:(NSString *)displayIdentifier;
- (id)applicationWithBundleIdentifier:(NSString *)bundleIdentifier;
- (void)uninstallApplication:(id)application;
@end

@interface SBRemoteNotificationServer : NSObject
+ (instancetype)sharedInstance;
- (int)registerApplication:(id)application forEnvironment:(NSString *)environment withTypes:(int)types;
- (void)unregisterApplication:(id)application;
- (NSArray *)_allPushRegisteredThirdPartyBundleIDs;
- (void)connection:(id)connection didReceiveIncomingMessage:(id)message;
- (void)connection:(id)connection
    didReceiveMessageForTopic:(NSString *)topic
                     userInfo:(NSDictionary *)userInfo;
@end

@interface UNNotificationRegistrarConnectionListener : NSObject
- (void)requestTokenForRemoteNotificationsForBundleIdentifier:(NSString *)bundleIdentifier withResult:(id)resultBlock;
- (void)invalidateTokenForRemoteNotificationsForBundleIdentifier:(NSString *)bundleIdentifier;
@end

/* iOS 10+ merged notification authorization and token requests into the
 * UserNotificationsServer connection listener. */
@interface UNSUserNotificationServerConnectionListener : NSObject
- (void)requestAuthorizationWithOptions:(NSUInteger)options
                    forBundleIdentifier:(NSString *)bundleIdentifier
                      completionHandler:(id)completionHandler;
- (void)requestTokenForRemoteNotificationsForBundleIdentifier:
            (NSString *)bundleIdentifier
                                      withCompletionHandler:(id)completionHandler;
- (void)invalidateTokenForRemoteNotificationsForBundleIdentifier:
            (NSString *)bundleIdentifier;
@end

@interface UNRemoteNotificationServer : NSObject
@end

@interface UNSUserNotificationServer : NSObject
+ (instancetype)sharedInstance;
@end

@interface UNCPushRegistrationRepository : NSObject
- (NSArray *)allBundleIdentifiers;
@end

@interface UNCNotificationRepository : NSObject
- (void)saveNotificationRequest:(UNNotificationRequest *)request
                   shouldRepost:(BOOL)shouldRepost
                    withMessage:(id)message
            forBundleIdentifier:(NSString *)bundleIdentifier;
@end

@interface UNCRemoteNotificationServer : NSObject
- (void)requestRemoteNotificationTokenWithEnvironment:(NSString *)environment
                                  forBundleIdentifier:(NSString *)bundleIdentifier;
- (void)invalidateTokenForRemoteNotificationsForBundleIdentifier:
    (NSString *)bundleIdentifier;
- (void)connection:(id)connection didReceiveIncomingMessage:(id)message;
- (BOOL)_queue_canDeliverMessageToBundle:(NSString *)bundleIdentifier;
- (BOOL)_queue_messageIsValidForDelivery:(id)message;
- (BOOL)_queue_isVisibleUserNotificationEnabledForApplication:
    (NSString *)bundleIdentifier;
- (void)_queue_didReceiveIncomingMessage:(id)message;
@end

@interface UNSNotificationSourceDescription : NSObject
+ (instancetype)sourceDescriptionWithBundleIdentifier:
    (NSString *)bundleIdentifier;
+ (instancetype)applicationSourceDescriptionWithApplication:(id)application;
- (NSString *)pushEnvironment;
@end

@interface LSApplicationProxy : NSObject
+ (instancetype)applicationProxyForIdentifier:(NSString *)bundleIdentifier;
@end

@interface UNSNotificationAuthorizationService : NSObject
- (void)requestAuthorizationWithOptions:(NSUInteger)options
    forNotificationSourceDescription:(id)source
    completionHandler:(void (^)(BOOL granted, NSError *error))completion;
- (void)requestRemoveAuthorizationForNotificationSourceDescription:(id)source
    completionHandler:(void (^)(BOOL removed, NSError *error))completion;
@end

@interface UNSSettingsGateway : NSObject
- (void)setSectionInfo:(id)sectionInfo forSectionID:(NSString *)sectionIdentifier;
- (id)sectionInfoForSectionID:(NSString *)sectionIdentifier;
- (id)_queue_sectionInfoForSectionID:(NSString *)sectionIdentifier;
@end

@interface SBRemoteNotificationClient : NSObject
- (instancetype)initWithBundleIdentifier:(NSString *)bundleIdentifier;
- (void)setEnvironment:(id)environment;
- (id)environment;
- (int)appEnabledTypes;
- (void)setAppEnabledTypes:(int)types;
- (int)settingsPresentedTypes;
- (void)setSettingsPresentedTypes:(int)types;
- (void)setLastKnownDeviceToken:(NSData *)token;
@end

@interface SBApplicationPersistence : NSObject
+ (instancetype)sharedInstance;
- (void)setArchivedObject:(id)object forKey:(NSString *)key bundleOrDisplayIdentifier:(NSString *)identifier;
@end

@interface SBRemoteNotificationPermissionAlert : NSObject
- (instancetype)initWithApplication:(id)application notificationTypes:(int)types;
@end

@interface SBAlertItemsController : NSObject
+ (instancetype)sharedInstance;
- (void)deactivateAlertItemsOfClass:(Class)alertClass;
- (void)activateAlertItem:(id)alert;
@end

@interface SBRemoteApplication : NSObject
- (void)remoteNotificationRegistrationSucceededWithDeviceToken:(NSData *)deviceToken;
- (void)remoteNotificationRegistrationFailedWithError:(NSError *)error;
@end

@interface NSObject (SGNAppExtras)
- (NSString *)bundleIdentifier;
- (SBRemoteApplication *)remoteApplication;
@end
