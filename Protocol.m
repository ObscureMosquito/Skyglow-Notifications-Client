#import "Protocol.h"
#include <Foundation/NSObjCRuntime.h>
#include <Foundation/Foundation.h>
#include <objc/NSObjCRuntime.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

typedef enum {
    Hello = 0,
    LoginChallenge = 1,
    RecieveNotification = 2,
    AuthenticationSuccessful = 3,
    ServerDisconnect = 4,
    DeviceTokenRegisterAck = 5,
} MessageTypesRecieved;

typedef enum {
    LoginRequest = 0,
    LoginChallengeResponse = 1,
    PollUnackedNotifications = 2,
    AckNotification = 3,
    ClientDisconnect = 4,
    RegisterDeviceToken = 5,
} MessageTypesSent;

NSString *connectionStatus = @"Disconnected";

id<NotificationDelegate> notificationDelegate = nil;

void setNotificationDelegate(id<NotificationDelegate> delegate) { // Objc is hard
    notificationDelegate = delegate;
}

SSL *ssl = nil;
SSL_CTX *sslctx = nil;
int sock = -1;

// User info
NSString *user_address = nil;
RSA *user_privKey = nil;

void sendMessage(MessageTypesSent messageType, NSMutableDictionary *dataToSend) {
    NSLog(@"Sending message with type %u", messageType);
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
    sendMessage(PollUnackedNotifications, [[NSMutableDictionary alloc] init]);
}
void ackNotification(NSString *notificationUUID) {
    NSMutableDictionary *dict = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                notificationUUID, @"notification", 
                                nil];
    sendMessage(AckNotification, dict);
}

void registerDeviceToken(NSData *deviceTokenChecksum, NSString *bundleId) {
    NSMutableDictionary *dict = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                deviceTokenChecksum, @"deviceTokenChecksum", 
                                bundleId, @"appBundleId", 
                                nil];
    sendMessage(RegisterDeviceToken, dict);
}

int connectToServer(const char *serverIP, int port, NSString *serverCert) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = SSLv23_client_method(); // TODO: Update this to a newer version of OpenSSL god dam!
    sslctx = SSL_CTX_new(method);
    if (!sslctx) {
        connectionStatus = @"InternalError";
        NSLog(@"Failed to create SSL_CTX");
        return 1;
    }

    SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3); // turn this from awful to slightly less awful

    // import server SSL certificate
    BIO *bio = BIO_new_mem_buf((void*)[serverCert UTF8String], -1);
    if (!bio) {
        connectionStatus = @"ServerSSLCertLoadFailure";
        NSLog(@"Failed to create memory BIO for certificate");
        SSL_CTX_free(sslctx);
        return 2;
    }

    X509 *cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
    if (!cert) {
        connectionStatus = @"ServerSSLCertLoadFailure";
        NSLog(@"Failed to parse SSL Certificate data");
        BIO_free(bio);
        SSL_CTX_free(sslctx);
        return 2;
    }

    X509_STORE *store = SSL_CTX_get_cert_store(sslctx);
    if (X509_STORE_add_cert(store, cert) != 1) {
        connectionStatus = @"ServerSSLCertLoadFailure";
        NSLog(@"Failed to add certificate to store");
        X509_free(cert);
        BIO_free(bio);
        SSL_CTX_free(sslctx);
        return 2;
    }

    X509_free(cert);
    BIO_free(bio);

    ssl = SSL_new(sslctx);
    if (!ssl) {
        connectionStatus = @"SSLObjectCreationFailue";
        NSLog(@"Failed to create SSL object");
        SSL_CTX_free(sslctx);
        return 3;
    }

    struct sockaddr_in serverAddr;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        connectionStatus = @"SocketCreationFailure";
        perror("Error creating socket");
        SSL_free(ssl);
        SSL_CTX_free(sslctx);
        sock = -1;
        return 4;
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
        return 5;
    }

    printf("Trying to connect...\n");
    if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        connectionStatus = @"FailedToConnect";
        perror("Error connecting to server");
        close(sockfd);
        sock = -1;
        return 6;
    }

    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) != 1) {
        connectionStatus = @"SSLConnectionStartFailure";
        ERR_print_errors_fp(stderr);
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(sslctx);
        sock = -1;
        return 7;
    }

    connectionStatus = @"ConnectedNotAuthenticated";
    printf("Connected successfully to %s on port %d\n", serverIP, port);
    return 0;
}


void dealloc() {
    RSA_free(user_privKey);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(sslctx);
    close(sock);
    connectionStatus = @"Disconnected";
}

// 0 = normal
// 1 = server requested disconnect
// 2 = critical error (probably disconnect?)
// 3 = data read error
// 4 = auth fail
int handleMessage() {
    NSError *error = nil;
    uint32_t length = 0;
    if (SSL_read(ssl, &length, 4) != 4) {
        NSLog(@"Failed to read reply length");
        return 3;
    }
    length = ntohl(length);

    NSMutableData *recievedDataRaw = [NSMutableData dataWithLength:length];
    if (SSL_read(ssl, [recievedDataRaw mutableBytes], length) != length) {
        NSLog(@"Failed to read payload");
        return 3;
    }

    NSDictionary *recievedData = [NSPropertyListSerialization propertyListWithData:recievedDataRaw
                                                                    options:NSPropertyListImmutable
                                                                     format:nil
                                                                      error:&error];
    if (!recievedData) {
        NSLog(@"Deserialization error: %@", error);
        return 2;
    }

    MessageTypesRecieved messageType = [recievedData[@"$type"] unsignedIntegerValue];
    NSLog(@"Recived a message of type %u", messageType);
    
    switch (messageType) {
        case Hello: {
            // some logic to start authentication?
            if (notificationDelegate != nil) {
                [notificationDelegate handleWelcomeMessage];
            } else {
                NSLog(@"Warning: Hello message received but no delegate is set to handle it");
                return 2;
            }
            return 0;
        }

        case LoginChallenge:{
            NSData *challengeEncrypted = recievedData[@"challenge"];

            // allocate the decrypted payload buffer? I don't get this.
            const size_t rsaSize = RSA_size(user_privKey);
            unsigned char *decryptedBytes = malloc(rsaSize);
            if (!decryptedBytes) {
                NSLog(@"Failed to allocate memory for decryption");
                dealloc();
                return 2;
            }

            // decrypt payload
            int resultLength = RSA_private_decrypt((int)[challengeEncrypted length], [challengeEncrypted bytes], decryptedBytes, user_privKey, RSA_PKCS1_OAEP_PADDING);
            if (resultLength == -1) {
                free(decryptedBytes);
                char errorBuf[120];
                ERR_load_crypto_strings();
                ERR_error_string(ERR_get_error(), errorBuf);
                NSLog(@"Decryption Error: %s", errorBuf);
                return 2;
            }

            NSData *decryptedData = [NSData dataWithBytesNoCopy:decryptedBytes length:resultLength freeWhenDone:YES];
            NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
            NSArray *challengeData = [decryptedString componentsSeparatedByString:@","];
            // user@example.com,Nonce,Timestamp

            if (![challengeData[0] isEqualToString:user_address]) {
                // reject
                NSLog(@"Invalid Challenge! User address %@ (expected %@)", challengeData[0],user_address);
                return 4;
            }

            
            NSTimeInterval challengeTimestamp = [challengeData[2] doubleValue];
            NSDate *now = [NSDate date];
            NSTimeInterval nowEpoch = [now timeIntervalSince1970];

            // Calculate bounds
            NSTimeInterval lowerBound = nowEpoch - 5 * 60;  // 5 minutes ago
            NSTimeInterval upperBound = nowEpoch + 1 * 60;  // 1 minute in the future
            if (challengeTimestamp < lowerBound || challengeTimestamp > upperBound) {
                // reject
                NSLog(@"Invalid Challenge! Timestamp check failed! (got %@)", challengeData[2]);
                return 4;
            }

            NSMutableDictionary *challengeResponce = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                challengeData[1], @"nonce", 
                                challengeData[2], @"timestamp",
                                nil];
            sendMessage(LoginChallengeResponse, challengeResponce);
            return 0;
        }
        case AuthenticationSuccessful: {
            // yippee
            connectionStatus = @"Connected"; // wooooo
            NSLog(@"Sucessfully logged into server!");
            
            [notificationDelegate authenticationSuccessful];

            // lets go check offline notifications
            checkOfflineNotifications();
            return 0;
        }
        case RecieveNotification:
            if (notificationDelegate != nil) {
                [notificationDelegate processNotificationMessage:recievedData];
            } else {
                NSLog(@"Warning: Notification received but no delegate is set to handle it");
                return 2;
            }
            return 0;
        case DeviceTokenRegisterAck:
            if (notificationDelegate != nil && 
                [notificationDelegate respondsToSelector:@selector(deviceTokenRegistrationCompleted:)]) {
                [notificationDelegate deviceTokenRegistrationCompleted:recievedData[@"bundleId"]];
            }
            return 0;
        case ServerDisconnect:
            connectionStatus = @"Disconnected";
            dealloc();
            return 1;
        default:
        // fallback, should i disconnect instead?
            return 0;
    }

}


void startLogin(NSString *address, RSA *auth_privKey, NSString *language) {
    user_address = address;
    user_privKey = auth_privKey;
    NSMutableDictionary *dict = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                address, @"address", 
                                protocolVersion, @"version",
                                language, @"lang",
                                nil];
    sendMessage(LoginRequest, dict);
}