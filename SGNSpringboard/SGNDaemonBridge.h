#import <Foundation/Foundation.h>
#import "SGControlChannelProtocol.h"

/* The SpringBoard side of the daemon IPC */

/* Bring up the SGControlChannel server */
void StartSpringBoardControlChannel(void);
void StartDaemonControlChannelClient(void);

/* Sends a bundle-scoped command to the daemon */
void SGNSendBundleCommand(SGControlMessageType messageType,
                          NSString *bundleId,
                          NSString *inboxEventPathToRemove);

/* Records a durable uninstall and tells the daemon to delete the app's state. */
void SGNSendDeleteAppCommand(NSString *bundleId);

/* Two-pass startup sweep that recovers uninstalls whose hook never fired. */
void SGNScheduleInstalledApplicationReconciliation(void);

/* Asks the daemon for an app's Skyglow token and delivers it. Completion is
 * called only after token persistence has succeeded or definitively failed. */
void SGN_AsyncFetchAndDeliverToken(NSString *bundleId, id application,
                                   id environment, int notificationTypes,
                                   void (^completion)(SGControlError error,
                                                      NSString *detail));

/* The SBRemoteApplication proxy for a bundle, or nil. */
id SGN_RemoteAppForBundle(NSString *bundleId);
