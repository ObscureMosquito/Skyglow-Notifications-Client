#include <Foundation/Foundation.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <SystemConfiguration/SCNetworkReachability.h>
#import <openssl/ssl.h>
#import <openssl/err.h>

#define protocolVersion "1.0.0"

NSString *connectionStatus = @"NotConnected";

void startLogin(NSString *address, RSA *auth_privKey);
void connectToServer(const char *serverIP, int port, NSString *serverCert);