#ifndef SKYGLOW_MAIN_H
#define SKYGLOW_MAIN_H

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
#import "AppMachMsgs.h"

#define MAX_BACKOFF 256

// Darwin Notifications for settings statuses
#define kDaemonStatusNewStatus "com.skyglow.snd.request_update"

#define kStatusDisabled                    @"Disabled"
#define kStatusError                       @"Error"
#define kStatusErrorInAuth                 @"ErrorInAuth"
#define kStatusEnabledNotConnected         @"EnabledNotConnected"
#define kStatusConnectedNotAuthenticated   @"ConnectedNotAuthenticated"
#define kStatusConnected                   @"Connected"
#define kStatusConnectionClosed            @"ConnectionClosed"
#define kStatusServerConfigBad             @"ServerConfigBad"

void updateStatus(NSString *status);
static void ReachabilityCallback(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags flags, void *info);

@interface NotificationDaemon : NSObject <NotificationDelegate> {
    SCNetworkReachabilityRef _reachabilityRef;
    NSMutableArray *_disconnectionTimes;
    BOOL _isRunning;
}

- (void)startMonitoringNetworkReachability;
- (void)exponentialBackoffConnect;

@end

#endif /* SKYGLOW_MAIN_H */