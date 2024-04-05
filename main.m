#import "main.h"


@implementation NotificationDaemon

- (void)scheduleLocalNotificationWithDecryptedMessage:(NSString *)decryptedMessage {
    // Parse the JSON string
    NSData *data = [decryptedMessage dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *messageDict = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    
    NSString *sender = messageDict[@"sender"];
    NSString *message = messageDict[@"message"];
    NSString *bundleID = messageDict[@"topic"]; // Assuming 'topic' is the bundle ID

    // Continue with your existing setup, but modify the notification details based on the message
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
}


- (void)exponentialBackoffConnect {
    NSLog(@"[ExponentialBackoffConnect] Started connection attempts");
    int serverPort;
    int sockfd;
    int backoff = 1;

    while (1) {
        serverPort = atoi(serverPortStr);
        NSLog(@"[ExponentialBackoffConnect] Converted server port string to integer: %d", serverPort);

        sockfd = connectToServer(serverIP, serverPort);
        if (sockfd <= 0) {
            NSLog(@"[ExponentialBackoffConnect] Connection failed with sockfd value: %d. Retrying in %d seconds...", sockfd, backoff);
            sleep(backoff);
            backoff *= 2; // Double the backoff time
            if (backoff > MAX_BACKOFF) { // Cap the backoff time to MAX_BACKOFF seconds
                backoff = MAX_BACKOFF;
                NSLog(@"[ExponentialBackoffConnect] Backoff reached maximum limit: %d seconds", MAX_BACKOFF);
            }
            continue; // Retry connection
        }

        NSLog(@"[ExponentialBackoffConnect] Connected to server at %s:%d", serverIP, serverPort);
        char buffer[1024];
        ssize_t bytesRead;

        while ((bytesRead = recv(sockfd, buffer, sizeof(buffer) - 1, 0)) > 0) {
            buffer[bytesRead] = '\0';
            NSString *base64EncodedString = [NSString stringWithUTF8String:buffer];
            NSData *decodedData = OpenSSLBase64Decode(base64EncodedString);

            // Adjust the tlsDecrypt call
            NSData *decryptedData = tlsDecrypt(decodedData, privateKeyPath); // Now privateKeyPath is an NSString*

            if (decryptedData) {
                NSString *decryptedMessageNSString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
                [self scheduleLocalNotificationWithDecryptedMessage:decryptedMessageNSString];
                NSLog(@"[ExponentialBackoffConnect] Received and decrypted message: %@", decryptedMessageNSString);
            } else {
                NSLog(@"[ExponentialBackoffConnect] Decryption failed.");
            }
        }

        if (bytesRead == 0) {
            NSLog(@"[ExponentialBackoffConnect] Server closed the connection. Reconnecting...");
        } else if (bytesRead < 0) {
            perror("[ExponentialBackoffConnect] recv error");
        }

        close(sockfd); // Close the socket before reconnecting
        NSLog(@"[ExponentialBackoffConnect] Socket closed, preparing for next connection attempt.");
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
            if (!SCNetworkReachabilitySetDispatchQueue(_reachabilityRef, backgroundQueue)) {
                NSLog(@"Could not set reachability dispatch queue");
            }
        } else {
            NSLog(@"Could not set reachability callback");
        }
    } else {
        NSLog(@"Failed to create reachability reference");
    }
}


static void ReachabilityCallback(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags flags, void *info) {
    BOOL isReachable = flags & kSCNetworkFlagsReachable;
    BOOL needsConnection = flags & kSCNetworkFlagsConnectionRequired;

    // Additional checks to ensure more accurate status
    BOOL isReachableWithoutRequiredConnection = isReachable && !needsConnection;
    
    NotificationDaemon *daemon = (__bridge NotificationDaemon *)info;
    
    if (isReachableWithoutRequiredConnection) {
        NSLog(@"Network became reachable, trying to connect.");
        [daemon exponentialBackoffConnect];
    } else {
        NSLog(@"Network became unreachable.");
        // Implement any additional logic for handling network unreachability
    }
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

    // Convert IPv4 and IPv6 addresses from text to binary form
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


int main() {
    @autoreleasepool {
        NSLog(@"Speedy Execution Is The Mother Of Good Fortune");
        NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
        NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];
        if (!prefs) {
            NSLog(@"Failed to read preferences.");
            return -1;
        }

        NotificationDaemon *daemon = [[NotificationDaemon alloc] init];
        [daemon startMonitoringNetworkReachability];

        NSString *ip = [prefs objectForKey:@"notificationServerAddress"];
        NSString *port = [prefs objectForKey:@"notificationServerPort"];
        BOOL isEnabled = [[prefs objectForKey:@"enabled"] boolValue];
        if (!isEnabled) {
            NSLog(@"[Main] Daemon is disabled, aborting");
            return 0;
        } else if (ip && port) {

            if (serverIP) free(serverIP); // Free previously allocated memory if any
            if (serverPortStr) free(serverPortStr); // Free previously allocated memory if any

            serverIP = strdup([ip UTF8String]);
            serverPortStr = strdup([port UTF8String]);

            // NSLog(@"[Main] Address and port extracted from preference file: %s,%s", serverIP, serverPortStr);

        } else if (!isReachableWithoutRequiredConnection) {
        // If network is not reachable, stay dormant until startMonitoringNetworkReachability deems it reachable.
            NSLog(@"[Main] Network is not reachable, staying dormant.");
        } else {
            NSLog(@"[Main] IP or Port missing in preferences.");
            return -1;
        }

        [daemon exponentialBackoffConnect];

        // Cleanup global variables
        if (serverIP) free(serverIP);
        if (serverPortStr) free(serverPortStr);
    }
    NSLog(@"Skyglow Notifications Daemon exited sucesfully");
    return 0;
}
