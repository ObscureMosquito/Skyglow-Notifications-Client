#import "main.h"

@implementation NotificationDaemon

- (void)scheduleLocalNotificationWithDecryptedMessage:(NSString *)decryptedMessage sockfd:(int)sockfd {
    // Parse the JSON string
    NSData *data = [decryptedMessage dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *messageDict = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];

    NSString *sender = messageDict[@"sender"];
    NSString *message = messageDict[@"message"];
    NSString *bundleID = messageDict[@"topic"]; // 'topic' is the bundle ID
    NSString *messageID = messageDict[@"message_id"];

    Class UILocalNotificationClass = NSClassFromString(@"UILocalNotification");
    if (!UILocalNotificationClass) {
        NSLog(@"UILocalNotification class not found.");
        return;
    }

    id localNotification = [[UILocalNotificationClass alloc] init];

    NSString *alertBody;
    if (sender) {
        alertBody = [NSString stringWithFormat:@"%@: %@", sender, message];
    } else {
        alertBody = message; // Use the message directly if no sender is provided
    }

    // Set the dynamically determined properties
    [localNotification performSelector:@selector(setAlertBody:) withObject:alertBody];
    [localNotification performSelector:@selector(setAlertAction:) withObject:@"Open"];
    [localNotification performSelector:@selector(setSoundName:) withObject:UILocalNotificationDefaultSoundName];

    // Check for the presence of "extra" key and conditionally include it
    NSMutableDictionary *userInfo = [NSMutableDictionary dictionary];
    if (messageDict[@"extra"]) { // Check if "extra" key exists
        userInfo[@"extra"] = messageDict[@"extra"];
    }

    if (messageDict[@"extra1"]) { // Check if "extra" key exists
        userInfo[@"extra1"] = messageDict[@"extra1"];
    }

    if (messageDict[@"extra2"]) { // Check if "extra" key exists
        userInfo[@"extra2"] = messageDict[@"extra2"];
    }

    if (messageDict[@"extra3"]) { // Check if "extra" key exists
        userInfo[@"extra3"] = messageDict[@"extra3"];
    }

    if (userInfo.count > 0) {
        NSLog(@"Setting userInfo with data: %@", [userInfo copy]);
        [localNotification performSelector:@selector(setUserInfo:) withObject:[userInfo copy]];
    }

    // Find the SBSLocalNotificationClient class and schedule the notification
    Class SBSLocalNotificationClientClass = objc_getClass("SBSLocalNotificationClient");
    if (SBSLocalNotificationClientClass) {
        SEL scheduleSelector = @selector(scheduleLocalNotification:bundleIdentifier:waitUntilDone:);
        if ([SBSLocalNotificationClientClass respondsToSelector:scheduleSelector]) {
            // Dynamically call the method to schedule the notification
            ((void (*)(id, SEL, id, id, char))objc_msgSend)(SBSLocalNotificationClientClass, scheduleSelector, localNotification, bundleID, (char)NO);
        } else {
            NSLog(@"SBSLocalNotificationClient does not respond to selector scheduleLocalNotification:bundleIdentifier:waitUntilDone:.");
        }
    } else {
        NSLog(@"SBSLocalNotificationClient class not found.");
    }

    if (messageID) {
        NSString *ackMessage = [NSString stringWithFormat:@"ACK:%@", messageID];
        NSLog(@"Preparing to send acknowledgment for message ID: %@", messageID);

        // Encrypt the acknowledgment message
        NSString *publicKeyPath = @"/Library/PreferenceBundles/SkyglowNotificationsDaemonSettings.bundle/Keys/public_key.pem";
        NSData *ackData = [ackMessage dataUsingEncoding:NSUTF8StringEncoding];
        NSData *encryptedAckData = encryptWithRSAPublicKey(ackData, publicKeyPath);

        if (!encryptedAckData) {
            NSLog(@"Failed to encrypt acknowledgment message");
            return;
        }

        // Send the encrypted acknowledgment
        ssize_t bytesSent = send(sockfd, [encryptedAckData bytes], [encryptedAckData length], 0);
        if (bytesSent == -1) {
            perror("Failed to send acknowledgment");
        } else {
            NSLog(@"Acknowledgment sent for message ID: %@", messageID);
        }
    }
}

- (void)exponentialBackoffConnect {
    NSLog(@"[ExponentialBackoffConnect] Started connection attempts");
    int serverPort;
    int sockfd;
    int backoff = 1;
    NSString *clientUUID = [self getClientUUID];

    // Encrypt the UUID with the server's public key
    NSString *publicKeyPath = @"/Library/PreferenceBundles/SkyglowNotificationsDaemonSettings.bundle/Keys/public_key.pem";
    NSData *uuidData = [clientUUID dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encryptedUUIDData = encryptWithRSAPublicKey(uuidData, publicKeyPath);

    if (!encryptedUUIDData) {
        NSLog(@"Failed to encrypt UUID");
        postDaemonStatusNotification(kDaemonStatusEncryptError);
        return;
    }

    postDaemonStatusNotification(kDaemonStatusEnabledNotConnected);

    while (1) {
        serverPort = atoi(serverPortStr);
        NSLog(@"[ExponentialBackoffConnect] Converted server port string to integer: %d", serverPort);

        if (serverPort <= 0) {
            NSLog(@"[ExponentialBackoffConnect] Invalid server port: %d", serverPort);
            postDaemonStatusNotification(kDaemonStatusBadPort);
            return;
        }

        sockfd = connectToServer(serverIP, serverPort);
        if (sockfd <= 0) {
            NSLog(@"[ExponentialBackoffConnect] Connection failed with sockfd value: %d. Retrying in %d seconds...", sockfd, backoff);
            sleep(backoff);
            backoff *= 2;
            if (backoff > MAX_BACKOFF) { // Cap the backoff time to MAX_BACKOFF seconds
                backoff = MAX_BACKOFF;
                NSLog(@"[ExponentialBackoffConnect] Backoff reached maximum limit: %d seconds", MAX_BACKOFF);
            }
            continue; // Retry connection
        }

        postDaemonStatusNotification(kDaemonStatusConnected);

        NSLog(@"[ExponentialBackoffConnect] Connected to server at %s:%d", serverIP, serverPort);

        // Send encrypted UUID to the server
        ssize_t bytesSent = send(sockfd, [encryptedUUIDData bytes], [encryptedUUIDData length], 0);
        if (bytesSent != [encryptedUUIDData length]) {
            NSLog(@"[ExponentialBackoffConnect] Failed to send encrypted UUID to the server.");
            close(sockfd);
            postDaemonStatusNotification(kDaemonStatusEnabledNotConnected);
            continue; // Retry connection
        }

        char buffer[1024];
        ssize_t bytesRead;

        while ((bytesRead = recv(sockfd, buffer, sizeof(buffer) - 1, 0)) > 0) {
            buffer[bytesRead] = '\0';
            NSString *base64EncodedString = [NSString stringWithUTF8String:buffer];
            NSLog(@"Received Base64 Encoded Encrypted Message: %@", base64EncodedString);

            if (base64EncodedString == nil || [base64EncodedString length] == 0) {
                NSLog(@"Received invalid base64 encoded message.");
                continue;
            }

            NSData *decodedData = OpenSSLBase64Decode(base64EncodedString);
            NSLog(@"Decoded Base64 message: %@", decodedData);

            if (decodedData == nil) {
                NSLog(@"Failed to decode base64 encoded message.");
                continue;
            }

            NSData *decryptedData = tlsDecrypt(decodedData, privateKeyPath);

            if (decryptedData) {
                NSString *decryptedMessageNSString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
                NSLog(@"Decrypted Message: %@", decryptedMessageNSString);
                [self scheduleLocalNotificationWithDecryptedMessage:decryptedMessageNSString sockfd:sockfd];
                NSLog(@"[ExponentialBackoffConnect] Received and decrypted message: %@", decryptedMessageNSString);
            } else {
                NSLog(@"[ExponentialBackoffConnect] Decryption failed.");
                postDaemonStatusNotification(kDaemonStatusDecryptError);
            }
        }

        if (bytesRead == 0) {
            NSLog(@"[ExponentialBackoffConnect] Server closed the connection. Reconnecting...");
            postDaemonStatusNotification(kDaemonStatusConnectionClosed);
        } else if (bytesRead < 0) {
            perror("[ExponentialBackoffConnect] recv error");
            postDaemonStatusNotification(kDaemonStatusError);
        }

        close(sockfd); // Close the socket before reconnecting
        NSLog(@"[ExponentialBackoffConnect] Socket closed, preparing for next connection attempt.");
        postDaemonStatusNotification(kDaemonStatusEnabledNotConnected);
        backoff = 1; // Reset backoff for the next connection attempt
    }
}

- (void)dealloc {
    if (_reachabilityRef != NULL) {
        SCNetworkReachabilitySetCallback(_reachabilityRef, NULL, NULL);
        SCNetworkReachabilitySetDispatchQueue(_reachabilityRef, NULL);
        CFRelease(_reachabilityRef);
        _reachabilityRef = NULL;
        [super dealloc];
    }
}

- (void)startMonitoringNetworkReachability {
    struct sockaddr_in zeroAddress;
    memset(&zeroAddress, 0, sizeof(zeroAddress));
    zeroAddress.sin_len = sizeof(zeroAddress);
    zeroAddress.sin_family = AF_INET;

    _reachabilityRef = SCNetworkReachabilityCreateWithAddress(NULL, (const struct sockaddr *)&zeroAddress);
    if (_reachabilityRef) {
        SCNetworkReachabilityContext context = {0, (__bridge void *)(self), NULL, NULL, NULL};
        if (SCNetworkReachabilitySetCallback(_reachabilityRef, ReachabilityCallback, &context)) {
            // Use a background queue to avoid blocking the main thread
            dispatch_queue_t backgroundQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
            if (SCNetworkReachabilitySetDispatchQueue(_reachabilityRef, backgroundQueue)) {
                NSLog(@"Reachability dispatch queue set successfully.");
            } else {
                NSLog(@"Could not set reachability dispatch queue");
            }
        } else {
            NSLog(@"Could not set reachability callback");
        }
    } else {
        NSLog(@"Failed to create reachability reference");
    }
}

- (SCNetworkReachabilityFlags)getReachabilityFlags {
    SCNetworkReachabilityFlags flags = 0;
    if (_reachabilityRef && SCNetworkReachabilityGetFlags(_reachabilityRef, &flags)) {
        return flags;
    }
    return 0;
}

- (NSString *)getClientUUID {
    NSString *uuidKey = @"clientUUID";
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-uuid.plist";
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    
    if (!prefs) {
        prefs = [NSMutableDictionary dictionary];
    }
    
    NSString *uuid = prefs[uuidKey];
    if (!uuid) {
        uuid = [[NSUUID UUID] UUIDString];
        prefs[uuidKey] = uuid;
        [prefs writeToFile:plistPath atomically:YES];
    }
    
    return uuid;
}

@end

int connectToServer(const char *serverIP, int port) {
    struct sockaddr_in serverAddr;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        return -1;
    } else {
        printf("Socket created successfully.\n");
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);

    int addr_status = inet_pton(AF_INET, serverIP, &serverAddr.sin_addr);
    if (addr_status <= 0) {
        if (addr_status == 0)
            fprintf(stderr, "inet_pton failed: Not in presentation format\n");
        else
            perror("inet_pton failed");
        close(sockfd);
        return -1;
    }

    printf("Trying to connect...\n");
    if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Error connecting to server");
        close(sockfd);
        return -1;
    }

    printf("Connected successfully to %s on port %d\n", serverIP, port);
    return sockfd;
}

static void ReachabilityCallback(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags flags, void *info) {
    BOOL isReachable = flags & kSCNetworkFlagsReachable;
    BOOL needsConnection = flags & kSCNetworkFlagsConnectionRequired;
    BOOL isReachableWithoutRequiredConnection = isReachable && !needsConnection;
    
    NotificationDaemon *daemon = (__bridge NotificationDaemon *)info;
    
    if (isReachableWithoutRequiredConnection) {
        NSLog(@"Network became reachable, trying to connect.");
        [daemon exponentialBackoffConnect];
    } else {
        NSLog(@"Network became unreachable.");
        postDaemonStatusNotification(kDaemonStatusEnabledNotConnected);
    }
}

void postDaemonStatusNotification(const char *status) {
    NSLog(@"postDaemonStatusNotification: Posting notification with status %s", status);

    CFStringRef notificationName;

    if (strcmp(status, kDaemonStatusDisabled) == 0) {
        notificationName = CFSTR(kDaemonStatusDisabled);
    } else if (strcmp(status, kDaemonStatusError) == 0) {
        notificationName = CFSTR(kDaemonStatusError);
    } else if (strcmp(status, kDaemonStatusEnabledNotConnected) == 0) {
        notificationName = CFSTR(kDaemonStatusEnabledNotConnected);
    } else if (strcmp(status, kDaemonStatusConnected) == 0) {
        notificationName = CFSTR(kDaemonStatusConnected);
    } else if (strcmp(status, kDaemonStatusBadPort) == 0) {
        notificationName = CFSTR(kDaemonStatusBadPort);
    } else if (strcmp(status, kDaemonStatusBadIP) == 0) {
        notificationName = CFSTR(kDaemonStatusBadIP);
    } else if (strcmp(status, kDaemonStatusDecryptError) == 0) {
        notificationName = CFSTR(kDaemonStatusDecryptError);
    } else if (strcmp(status, kDaemonStatusEncryptError) == 0) {
        notificationName = CFSTR(kDaemonStatusEncryptError);
    } else if (strcmp(status, kDaemonStatusConnectionClosed) == 0) {
        notificationName = CFSTR(kDaemonStatusConnectionClosed);
    } else {
        NSLog(@"postDaemonStatusNotification: Unknown status.");
        return;
    }

    // Post the notification
    CFNotificationCenterPostNotificationWithOptions(CFNotificationCenterGetDarwinNotifyCenter(),
                                                    notificationName,
                                                    NULL,
                                                    NULL,
                                                    kCFNotificationDeliverImmediately);

    NSLog(@"postDaemonStatusNotification: Notification posted successfully.");
}

BOOL isValidIPAddress(NSString *ipAddress) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, [ipAddress UTF8String], &(sa.sin_addr));
    return result == 1;
}

BOOL isValidPort(NSString *port) {
    if (port.length == 0) return NO;
    NSCharacterSet *nonDigits = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
    return [port rangeOfCharacterFromSet:nonDigits].location == NSNotFound;
}

int main() {
    @autoreleasepool {
        NSLog(@"Speedy Execution Is The Mother Of Good Fortune");
        NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
        NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];
        if (!prefs) {
            NSLog(@"Failed to read preferences.");
            postDaemonStatusNotification(kDaemonStatusError);
            return -1;
        }

        NotificationDaemon *daemon = [[NotificationDaemon alloc] init];
        [daemon startMonitoringNetworkReachability];

        NSString *ip = [prefs objectForKey:@"notificationServerAddress"];
        NSString *port = [prefs objectForKey:@"notificationServerPort"];
        BOOL isEnabled = [[prefs objectForKey:@"enabled"] boolValue];

        if (!isEnabled) {
            NSLog(@"[Main] Daemon is disabled, aborting");
            postDaemonStatusNotification(kDaemonStatusDisabled);
            return 0;
        }

        if (ip == nil || !isValidIPAddress(ip)) {
            NSLog(@"[Main] Invalid or missing IP address in preferences.");
            postDaemonStatusNotification(kDaemonStatusBadIP);
            return -1;
        }

        if (port == nil || !isValidPort(port)) {
            NSLog(@"[Main] Invalid or missing port in preferences.");
            postDaemonStatusNotification(kDaemonStatusBadPort);
            return -1;
        }

        if (serverIP) free(serverIP); // Free previously allocated memory if any
        if (serverPortStr) free(serverPortStr); // Free previously allocated memory if any

        serverIP = strdup([ip UTF8String]);
        serverPortStr = strdup([port UTF8String]);

        NSLog(@"[Main] Address and port extracted from preference file: %s,%s", serverIP, serverPortStr);

        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 2, false);

        // Check initial reachability status
        SCNetworkReachabilityFlags flags = [daemon getReachabilityFlags];
        BOOL isReachable = flags & kSCNetworkFlagsReachable;
        BOOL needsConnection = flags & kSCNetworkFlagsConnectionRequired;
        BOOL isReachableWithoutRequiredConnection = isReachable && !needsConnection;

        if (!isReachableWithoutRequiredConnection) {
            NSLog(@"[Main] Initial network check: Network is not reachable, staying dormant.");
            postDaemonStatusNotification(kDaemonStatusEnabledNotConnected);
        } else {
            [daemon exponentialBackoffConnect];
        }

        // Cleanup global variables
        if (serverIP) free(serverIP);
        if (serverPortStr) free(serverPortStr);
    }
    NSLog(@"Skyglow Notifications Daemon exited successfully");
    return 0;
}
