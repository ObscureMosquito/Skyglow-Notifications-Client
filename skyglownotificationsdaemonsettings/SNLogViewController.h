#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>

// Darwin Notification Statuses
#define kDaemonStatusNotification "com.skyglow.notificationdaemon.status"
#define kDaemonStatusKey "DaemonStatus"
#define kDaemonStatusDisabled "Disabled"
#define kDaemonStatusError "Error"
#define kDaemonStatusEnabledNotConnected "EnabledNotConnected"
#define kDaemonStatusConnected "Connected"
#define kDaemonStatusBadPort "DaemonStatusBadPort"
#define kDaemonStatusBadIP "DaemonStatusBadIP"
#define kDaemonStatusDecryptError "DaemonStatusDecryptError"
#define kDaemonStatusEncryptError "DaemonStatusEncryptError"
#define kDaemonStatusConnectionClosed "DaemonStatusConnectionClosed"

@interface SNLogViewController : UIViewController

- (void)updateLogWithStatus:(NSString *)status;

@end