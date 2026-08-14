#import <Foundation/Foundation.h>
#import "SGControlChannelProtocol.h"

NSArray *SGN_AllNativelyRegisteredBundles(void);
BOOL     SGN_BundleRegisteredWithNativePush(NSString *bundleId);

/** True while a native deregister cascade for this bundle is in flight. */
BOOL SGN_IsCascadeReEntry(NSString *bundleId);

void SGN_DeregisterAppNativelyWithCompletion(
    NSString *bundleId,
    void (^completion)(SGControlError error, NSString *detail));

/** Requests a real Apple Push registration without changing Skyglow state. */
void SGN_RegisterAppNativelyWithCompletion(
    NSString *bundleId,
    void (^completion)(SGControlError error, NSString *detail));

void SGN_DeliverSuccess(NSString *bundleId, id application, id environment,
                        int notificationTypes, NSData *token);

/** Prevents a late real-APNS token from overwriting a Skyglow token. */
void SGN_InstallTokenGuard(void);

BOOL SGNRegistrationConsumePassThrough(void);
void SGNRegistrationBeginPassThrough(void);
void SGNRegistrationEndPassThrough(void);
void SGNRegistrationPresentClassicChoice(id server, id application,
                                         id environment, NSString *bundleId,
                                         int notificationTypes);
void SGNRegistrationPresentModernChoice(id server, NSString *bundleId,
                                        id resultBlock,
                                        SEL requestSelector);
