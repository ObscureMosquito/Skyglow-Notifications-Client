#import "Protocol.h"
#include <Foundation/NSObjCRuntime.h>
#include <Foundation/Foundation.h>
#include "main.h"
#include <objc/NSObjCRuntime.h>

typedef enum {
    Hello,
    LoginChallenge,
    RecieveNotification,
    AuthenticationSuccessful,
    ServerDisconnect,
} MessageTypesRecieved;

typedef enum {
    LoginRequest,
    LoginChallengeResponse,
    PollUnackedNotifications,
    AckNotification,
    ClientDisconnect,
} MessageTypesSent;

SSL *ssl = nil;
SSL_CTX *sslctx = nil;
int sock = -1;

// User info
NSString *user_address = nil;
RSA *user_privKey = nil;

void sendMessage(MessageTypesSent messageType, NSMutableDictionary *dataToSend) {
    dataToSend[@"$type"] = @(messageType);

    NSError *error = nil;
    NSData *plistData = [NSPropertyListSerialization dataWithPropertyList:dataToSend
                                                                   format:NSPropertyListBinaryFormat_v1_0
                                                                  options:0
                                                                    error:&error];
    if (!plistData) {
        NSLog(@"Plist serialization error: %@", error);
        return;
    }

    uint32_t length = htonl((uint32_t)[plistData length]);
    SSL_write(ssl, &length, 4);
    SSL_write(ssl, [plistData bytes], (int)[plistData length]);
}

void checkOfflineNotifications() {
    sendMessage(PollUnackedNotifications, [NSMutableDictionary alloc]);
}
void ackNotification(NSString *notificationUUID) {
    NSMutableDictionary *dict = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                notificationUUID, @"notification", 
                                nil];
    sendMessage(LoginRequest, dict);
}


void connectToServer(const char *serverIP, int port, NSString *serverCert) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = DTLS_client_method();
    sslctx = SSL_CTX_new(method);
    if (!sslctx) {
        connectionStatus = @"InternalError";
        NSLog(@"Failed to create SSL_CTX");
        return;
    }

    // import server SSL certificate
    if (SSL_CTX_load_verify_locations(sslctx, [serverCert UTF8String], nil) != 1) {
        connectionStatus = @"ServerSSLCertLoadFailure";
        NSLog(@"Failed to load server SSL Certificate");
        SSL_CTX_free(sslctx);
        return;
    }

    ssl = SSL_new(sslctx);
    if (!ssl) {
        connectionStatus = @"SSLObjectCreationFailue";
        NSLog(@"Failed to create SSL object");
        SSL_CTX_free(sslctx);
        return;
    }

    struct sockaddr_in serverAddr;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        connectionStatus = @"SocketCreationFailure";
        perror("Error creating socket");
        SSL_free(ssl);
        SSL_CTX_free(sslctx);
        sock = -1;
        return;
    }

    printf("Socket created successfully.\n");

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);

    int addr_status = inet_pton(AF_INET, serverIP, &serverAddr.sin_addr);
    if (addr_status <= 0) {
        if (addr_status == 0)
            fprintf(stderr, "inet_pton failed: Not in presentation format\n");
        else
            perror("inet_pton failed");
        connectionStatus = @"InvalidConnectionData";
        close(sockfd);
        sock = -1;
        return;
    }

    printf("Trying to connect...\n");
    if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        connectionStatus = @"FailedToConnect";
        perror("Error connecting to server");
        close(sockfd);
        sock = -1;
        return;
    }

    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) != 1) {
        connectionStatus = @"SSLConnectionStartFailure";
        ERR_print_errors_fp(stderr);
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(sslctx);
        sock = -1;
        return;
    }

    connectionStatus = @"ConnectedNotAuthenticated";
    printf("Connected successfully to %s on port %d\n", serverIP, port);
}


void dealloc() {
    RSA_free(user_privKey);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(sslctx);
    close(sock);
    connectionStatus = @"Disconnected";
}

void handleMessage(NotificationDaemon *daemon) {
    NSError *error = nil;
    uint32_t length = 0;
    if (SSL_read(ssl, &length, 4) != 4) {
        NSLog(@"Failed to read reply length");
        return;
    }
    length = ntohl(length);

    NSMutableData *recievedDataRaw = [NSMutableData dataWithLength:length];
    if (SSL_read(ssl, [recievedDataRaw mutableBytes], length) != length) {
        NSLog(@"Failed to read payload");
        return;
    }

    NSDictionary *recievedData = [NSPropertyListSerialization propertyListWithData:recievedDataRaw
                                                                    options:NSPropertyListImmutable
                                                                     format:nil
                                                                      error:&error];
    if (!recievedData) {
        NSLog(@"Deserialization error: %@", error);
    }

    MessageTypesRecieved messageType = [recievedData[@"$type"] unsignedIntegerValue];
    
    switch (messageType) {
        case Hello: {
            // some logic to start authentication?
            break;
        }

        case LoginChallenge:{
            NSData *challengeEncrypted = recievedData[@"challenge"];

            // allocate the decrypted payload buffer? I don't get this.
            const size_t rsaSize = RSA_size(user_privKey);
            unsigned char *decryptedBytes = malloc(rsaSize);
            if (!decryptedBytes) {
                NSLog(@"Failed to allocate memory for decryption");
                dealloc();
                return;
            }

            // decrypt payload
            int resultLength = RSA_private_decrypt((int)[challengeEncrypted length], [challengeEncrypted bytes], decryptedBytes, user_privKey, RSA_PKCS1_OAEP_PADDING);
            if (resultLength == -1) {
                free(decryptedBytes);
                char errorBuf[120];
                ERR_load_crypto_strings();
                ERR_error_string(ERR_get_error(), errorBuf);
                NSLog(@"Decryption Error: %s", errorBuf);
                dealloc();
                return;
            }

            NSData *decryptedData = [NSData dataWithBytesNoCopy:decryptedBytes length:resultLength freeWhenDone:YES];
            NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
            NSArray *challengeData = [decryptedString componentsSeparatedByString:@","];

            // user@example.com,Nonce,Timestamp

            if (challengeData[0] != user_address) {
                // reject
                dealloc();
                return;
            }

            
            NSTimeInterval challengeTimestamp = [challengeData[2] doubleValue];
            NSDate *now = [NSDate date];
            NSTimeInterval nowEpoch = [now timeIntervalSince1970];

            // Calculate bounds
            NSTimeInterval lowerBound = nowEpoch - 5 * 60;  // 5 minutes ago
            NSTimeInterval upperBound = nowEpoch + 1 * 60;  // 1 minute in the future
            if (challengeTimestamp >= lowerBound && challengeTimestamp <= upperBound) {
                // reject
                dealloc();
                return;
            }

            NSMutableDictionary *challengeResponce = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                challengeData[1], @"nonce", 
                                challengeData[2], @"timestamp",
                                nil];
            sendMessage(LoginChallengeResponse, challengeResponce);
            break;
        }
        case AuthenticationSuccessful: {
            // yippe

            // lets go check offline notifications
            checkOfflineNotifications();
            connectionStatus = @"Connected"; // wooooo
            NSLog(@"Sucessfully logged into server!");

        }
        case RecieveNotification:
            [daemon processNotificationMessage:recievedData];
            break;
        case ServerDisconnect:
            connectionStatus = @"Disconnected";
            dealloc();
            return;
        default:
            break;
    }
}


void startLogin(NSString *address, RSA *auth_privKey) {
    user_address = address;
    user_privKey = auth_privKey;
    NSMutableDictionary *dict = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                address, @"address", 
                                protocolVersion, @"version",
                                nil];
    sendMessage(LoginRequest, dict);
}