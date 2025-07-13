#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import "KeyManager.h"
#import "Protocol.h"

#define MAX_BACKOFF 256 // Maximum backoff time in seconds

// Darwin Notifications for settings statuses
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

// Global variables
char *serverIP;
char *serverPortStr;
NSString *privateKeyPath = @"/Library/PreferenceBundles/SkyglowNotificationsDaemonSettings.bundle/Keys/private_key.pem";
BOOL *isReachableWithoutRequiredConnection = NULL;

// Functions
static void ReachabilityCallback(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags flags, void *info);
void postDaemonStatusNotification(const char *status);

@interface NotificationDaemon : NSObject {
    SCNetworkReachabilityRef _reachabilityRef;
}

- (void)startMonitoringNetworkReachability;
- (void)exponentialBackoffConnect;
- (void)processNotificationMessage:(NSDictionary *)messageDict;
- (void)exponentialBackoffConnect;
@end