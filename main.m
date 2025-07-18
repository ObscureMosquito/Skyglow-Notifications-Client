#import "main.h"
#include <Foundation/NSObjCRuntime.h>
#include "openssl/pem.h"
#include "Protocol.h"
#include <Foundation/Foundation.h>

@implementation NotificationDaemon

- (void)processNotificationMessage:(NSDictionary *)messageDict {
    NSLog(@"Sending a notification");
    NSLog(@"Complete messageDict contents: %@", messageDict);

    NSString *alertBody = messageDict[@"message"];
    NSString *bundleID = messageDict[@"topic"]; // 'topic' is the bundle ID
    NSString *messageID = messageDict[@"message_id"];
    NSString *alertAction = messageDict[@"alert_action"];
    NSString *alertSound = messageDict[@"alert_sound"];

    NSLog(@"A notification has been recived. Topic: `%@`, Message: `%@`, Message ID: `%@`", bundleID, alertBody, messageID);

    NSMutableDictionary *userInfo = messageDict[@"user_info"];

    Class UILocalNotificationClass = NSClassFromString(@"UILocalNotification");
    if (!UILocalNotificationClass) {
        NSLog(@"UILocalNotification class not found.");
        return;
    }

    id localNotification = [[UILocalNotificationClass alloc] init];

    [localNotification performSelector:@selector(setAlertBody:) withObject:alertBody];
    [localNotification performSelector:@selector(setAlertAction:) withObject:alertAction];
    [localNotification performSelector:@selector(setSoundName:) withObject:alertSound];
    
    if (userInfo && userInfo.count > 0) {
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
        ackNotification(messageID);
    }
}

- (void)handleWelcomeMessage {
    // login time
    NSString *clientAddress = [self getClientAddress];
    RSA *privKey = [self getClientPrivKey];
    startLogin(clientAddress, privKey);
}

- (void)exponentialBackoffConnect {
    NSLog(@"[ExponentialBackoffConnect] Started connection attempts");
    int serverPort;
    int connectionResult;
    int backoff = 1;
    NSString *serverPubKey = [self getServerPubKey];

    postDaemonStatusNotification(kDaemonStatusEnabledNotConnected);

    while (1) {
        serverPort = atoi(serverPortStr);
        NSLog(@"[ExponentialBackoffConnect] Converted server port string to integer: %d", serverPort);

        if (serverPort <= 0) {
            NSLog(@"[ExponentialBackoffConnect] Invalid server port: %d", serverPort);
            postDaemonStatusNotification(kDaemonStatusBadPort);
            return;
        }

        setNotificationDelegate(self);

        // TODO: thiss section should probably be totally rewritten.
        connectionResult = connectToServer(serverIP, serverPort, serverPubKey);
        if (connectionResult != 0) {
            NSLog(@"[ExponentialBackoffConnect] Connection failed with sockfd value: %d. Retrying in %d seconds...", connectionResult, backoff);
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


        while (1) {
            // handle
            int result = handleMessage();
            switch (result) {
                case 0:
                break;

                case 1:
                case 2:
                case 3:
                case 4:
                goto disconnect;
            }
        }

        disconnect:
        close(connectionResult); // Close the socket before reconnecting
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

- (NSString *)getClientAddress {
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    
    if (!prefs) {
        return nil;
    }
    
    NSString *address = prefs[@"device_address"];
    
    return address;
}

- (NSString *)getServerPubKey {
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    
    if (!prefs) {
        return nil;
    }
    
    NSString *serverPubKeyString = prefs[@"server_pub_key"];
    return serverPubKeyString;
}

- (RSA *)getClientPrivKey {
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    
    if (!prefs) {
        return nil;
    }
    
    NSString *clientPrivateKeyString = prefs[@"privateKey"];
    if (!clientPrivateKeyString) {
        NSLog(@"No client private key found in preferences");
        return nil;
    }
    
    const char *pemData = [clientPrivateKeyString UTF8String];
    
    // Create a memory BIO
    BIO *bio = BIO_new_mem_buf((void *)pemData, -1); // -1 means calculate the length
    if (!bio) {
        NSLog(@"Failed to create memory BIO");
        return nil;
    }
    
    // Read the RSA key from the BIO
    RSA *clientPrivKey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    
    // Free the BIO
    BIO_free(bio);
    
    if (!clientPrivKey) {
        NSLog(@"Failed to parse RSA public key from string");
        return nil;
    }
    
    return clientPrivKey;
}

@end

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

        NSString *ip = @"10.0.0.77"; // TODO: This is hardcoded for now, this needs to be queried from the TXT record.
        NSString *port = @"7373";
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
