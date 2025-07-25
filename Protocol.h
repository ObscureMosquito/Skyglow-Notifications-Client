#include <Foundation/Foundation.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <SystemConfiguration/SCNetworkReachability.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define protocolVersion @"1.0.0"

extern NSString *connectionStatus;

@protocol NotificationDelegate <NSObject>
- (void)processNotificationMessage:(NSDictionary *)notificationData;
- (void)handleWelcomeMessage;
- (void)authenticationSuccessful;
- (void)deviceTokenRegistrationCompleted:(NSString *)bundleId;
@end


void startLogin(NSString *address, RSA *auth_privKey, NSString *language);
int connectToServer(const char *serverIP, int port, NSString *serverCert);
void ackNotification(NSString *notificationUUID);
int handleMessage();
void setNotificationDelegate(id<NotificationDelegate> delegate);
void registerDeviceToken(NSData *deviceTokenChecksum, NSString *bundleId);