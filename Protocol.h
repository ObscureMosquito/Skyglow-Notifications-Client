#ifndef SKYGLOW_PROTOCOL_H
#define SKYGLOW_PROTOCOL_H

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
@end

void startLogin(NSString *address, RSA *auth_privKey, NSString *language);
int connectToServer(const char *serverIP, int port, NSString *serverCert);
void disconnectFromServer(void);

/// Send a ClientDisconnect message before closing. Safe when not connected.
void sendClientDisconnect(void);

BOOL isConnected(void);
void ackNotification(NSString *notificationUUID, int status);
int handleMessage(void);
void setNotificationDelegate(id<NotificationDelegate> delegate);
void sendFeedback(NSData *routing_token, NSNumber *type, NSString *reason);

#endif /* SKYGLOW_PROTOCOL_H */