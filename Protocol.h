#include <Foundation/Foundation.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <SystemConfiguration/SCNetworkReachability.h>

#import <openssl/ssl.h>
#import <openssl/err.h>


#define protocolVersion "1.0.0"

NSString *connectionStatus = @"NotConnected";

// @protocol NotificationDaemon <NSObject>
// - (void)processNotificationMessage:(NSDictionary *)notificationData;
// @end

void startLogin(NSString *address, RSA *auth_privKey);
int connectToServer(const char *serverIP, int port, NSString *serverCert);
void ackNotification(NSString *notificationUUID);
// int handleMessage(id<NotificationDaemon>  *daemon);