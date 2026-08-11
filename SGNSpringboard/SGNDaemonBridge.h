#import <Foundation/Foundation.h>
#import "SGControlChannelProtocol.h"

void StartSpringBoardControlChannel(void);
void StartDaemonControlChannelClient(void);

void SGNSendBundleCommand(SGControlMessageType messageType,
                          NSString *bundleId,
                          NSString *inboxEventPathToRemove);

/** Records a durable uninstall and tells the daemon to delete the app's state. */
void SGNSendDeleteAppCommand(NSString *bundleId);

/** Two-pass startup sweep that recovers uninstalls whose hook never fired. */
void SGNScheduleInstalledApplicationReconciliation(void);

/** Completion fires only after token persistence succeeds or definitively fails. */
void SGN_AsyncFetchAndDeliverToken(NSString *bundleId, id application,
                                   id environment, int notificationTypes,
                                   void (^completion)(SGControlError error,
                                                      NSString *detail));

id SGN_RemoteAppForBundle(NSString *bundleId);
