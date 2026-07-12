#import <Foundation/Foundation.h>
#import "SGControlChannelProtocol.h"

/* Native  push registration state on this device */

/* Bundle ids Apple's push stack currently has registered. */
NSArray *SGN_AllNativelyRegisteredBundles(void);
BOOL     SGN_BundleRegisteredWithNativePush(NSString *bundleId);

/* True while a native deregister cascade for this bundle is in flight */
BOOL SGN_IsCascadeReEntry(NSString *bundleId);

/* Tears down Apple's native push registration for a bundle */
void SGN_DeregisterAppNatively(NSString *bundleId);
void SGN_DeregisterAppNativelyWithCompletion(
    NSString *bundleId,
    void (^completion)(SGControlError error, NSString *detail));

/* Requests a real Apple Push registration without changing Skyglow state. */
void SGN_RegisterAppNativelyWithCompletion(
    NSString *bundleId,
    void (^completion)(SGControlError error, NSString *detail));

/* Installs a SGN token into the native push client  */
void SGN_DeliverSuccess(NSString *bundleId, id application, id environment,
                        int notificationTypes, NSData *token);

/* Idempotently hooks native token delivery so a late real-APNS token can't
 * overwrite a Skyglow token for a SGN app */
void SGN_InstallTokenGuard(void);

/* Registration provider-choice flow */
BOOL SGNRegistrationConsumePassThrough(void);
void SGNRegistrationBeginPassThrough(void);
void SGNRegistrationEndPassThrough(void);
void SGNRegistrationPresentClassicChoice(id server, id application,
                                         id environment, NSString *bundleId,
                                         int notificationTypes);
void SGNRegistrationPresentModernChoice(id server, NSString *bundleId,
                                        id resultBlock);
