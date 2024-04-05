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

#define MAX_BACKOFF 256 // Maximum backoff time in seconds

// Global variables
char *serverIP;
char *serverPortStr;
NSString *privateKeyPath = @"/Library/PreferenceBundles/SkyglowNotificationsDaemonSettings.bundle/Keys/private_key.pem";
BOOL *isReachableWithoutRequiredConnection = NULL;

// Functions
int connectToServer(const char *serverIP, int port);
NSData *tlsDecrypt(NSData *inputData, NSString *privateKeyPath);

@interface NotificationDaemon : NSObject {
    SCNetworkReachabilityRef _reachabilityRef;
}

- (void)startMonitoringNetworkReachability;
- (void)exponentialBackoffConnect;
- (void)scheduleLocalNotificationWithDecryptedMessage:(NSString *)decryptedMessage;
- (void)exponentialBackoffConnect;
@end