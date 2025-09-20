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
#import "Protocol.h"
#import "MachMsgs.h"

#define MAX_BACKOFF 256 // Maximum backoff time in seconds

// Darwin Notifications for settings statuses
#define kDaemonStatusNewStatus "com.skyglow.snd.request_update"

#define kStatusDisabled @"Disabled"
#define kStatusError @"Error"
#define kStatusErrorInAuth @"ErrorInAuth"
#define kStatusEnabledNotConnected @"EnabledNotConnected"
#define kStatusConnectedNotAuthenticated @"ConnectedNotAuthenticated"
#define kStatusConnected @"Connected"
#define kStatusConnectionClosed @"ConnectionClosed"
#define kStatusServerConfigBad @"ServerConfigBad"


// Global variables
BOOL *isReachableWithoutRequiredConnection = NULL;
MachMsgs *machMsgs;

NSString *serverAddress = nil;
DBManager *db = nil;
char *serverIP = NULL;
char *serverPortStr = NULL;

// Functions
static void ReachabilityCallback(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags flags, void *info) __attribute__((used));
void updateStatus(NSString *status);

@interface NotificationDaemon :  NSObject <NotificationDelegate>  {
    SCNetworkReachabilityRef _reachabilityRef;
}

- (void)startMonitoringNetworkReachability;
- (void)exponentialBackoffConnect;
@end