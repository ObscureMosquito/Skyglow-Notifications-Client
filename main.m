#import "main.h"
#include <objc/NSObjCRuntime.h>
#include <CoreFoundation/CFBase.h>
#include "ServerLocationFinder.h"
#include <Foundation/NSObjCRuntime.h>
#include "openssl/pem.h"
#include "Protocol.h"
#include <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#import "CryptoManager.h"
#import "DBManager.h"
#import "TweakMachMessages.h"
#include <bootstrap.h>
#import "Globals.h"


static kern_return_t SendPush(NSString *topic, NSDictionary *userInfo) {
    if (topic == nil || topic.length == 0) {
        NSLog(@"[SendPush] Missing topic");
        return KERN_INVALID_ARGUMENT;
    }

    // Convert topic to UTF8 once (fail if cannot be represented)
    NSData *topicData = [topic dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
    if (!topicData || topicData.length == 0) {
        NSLog(@"[SendPush] Topic UTF8 conversion failed");
        return KERN_INVALID_ARGUMENT;
    }

    // Serialize payload (treat nil as empty dictionary)
    NSData *plistData = nil;
    if (userInfo) {
        NSError *err = nil;
        plistData = [NSPropertyListSerialization dataWithPropertyList:userInfo
                                                               format:NSPropertyListBinaryFormat_v1_0
                                                              options:0
                                                                error:&err];
        if (!plistData) {
            NSLog(@"[SendPush] Payload serialization failed: %@", err);
            return KERN_INVALID_ARGUMENT;
        }
    } else {
        plistData = [NSData data];
    }

    mach_port_t bootstrapPort = MACH_PORT_NULL;
    kern_return_t kr = task_get_bootstrap_port(mach_task_self(), &bootstrapPort);
    if (kr != KERN_SUCCESS || bootstrapPort == MACH_PORT_NULL) {
        NSLog(@"[SendPush] task_get_bootstrap_port: %s", mach_error_string(kr));
        return (kr == KERN_SUCCESS) ? KERN_FAILURE : kr;
    }

    mach_port_t servicePort = MACH_PORT_NULL;
    kr = bootstrap_look_up(bootstrapPort, SKYGLOW_MACH_SERVICE_NAME_PUSH, &servicePort);
    if (kr != KERN_SUCCESS || servicePort == MACH_PORT_NULL) {
        NSLog(@"[SendPush] bootstrap_look_up(%s): %s",
              SKYGLOW_MACH_SERVICE_NAME_PUSH, mach_error_string(kr));
        return (kr == KERN_SUCCESS) ? KERN_FAILURE : kr;
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winvalid-offsetof"
    const size_t maxInline = sizeof(((MachPushRequestMessage*)0)->userInfoData);
#pragma clang diagnostic pop

    // Refuse oversize payload instead of silent truncation
    if (plistData.length > maxInline) {
        NSLog(@"[SendPush] Payload too large (%lu > %lu) – refusing",
              (unsigned long)plistData.length, (unsigned long)maxInline);
        return KERN_RESOURCE_SHORTAGE;
    }

    MachPushRequestMessage msg;
    memset(&msg, 0, sizeof(msg));

    msg.header.msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_remote_port = servicePort;
    msg.header.msgh_id          = SKYGLOW_REQUEST_PUSH;
    msg.body.msgh_descriptor_count = 0;
    msg.type = SKYGLOW_REQUEST_PUSH;

    // topic
    size_t maxTopic = sizeof(msg.topic) - 1;
    size_t copyLen = MIN((size_t)topicData.length, maxTopic);
    memcpy(msg.topic, topicData.bytes, copyLen);
    msg.topic[copyLen] = '\0';
    if (copyLen < topicData.length) {
        NSLog(@"[SendPush] Topic truncated (%zu > %zu): %@",
              (size_t)topicData.length, maxTopic, topic);
    }

    msg.userInfoLength = (uint32_t)plistData.length;
    if (plistData.length) {
        memcpy(msg.userInfoData, plistData.bytes, plistData.length);
    }

    size_t usedSize = offsetof(MachPushRequestMessage, userInfoData) + plistData.length;
    // 4-byte align
    usedSize = (usedSize + 3) & ~(size_t)3;

    if (usedSize > sizeof(msg) || usedSize > UINT32_MAX) {
        NSLog(@"[SendPush] Internal size computation invalid (%zu)", usedSize);
        return KERN_INVALID_ARGUMENT;
    }
    msg.header.msgh_size = (mach_msg_size_t)usedSize;

    NSLog(@"[SendPush] topic='%@' payload=%u bytes totalMsgSize=%u",
          topic, msg.userInfoLength, msg.header.msgh_size);

    kr = mach_msg(&msg.header,
                  MACH_SEND_MSG,
                  msg.header.msgh_size,
                  0,
                  MACH_PORT_NULL,
                  MACH_MSG_TIMEOUT_NONE,
                  MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[SendPush] mach_msg send failed: %s (%d)",
              mach_error_string(kr), kr);
    }
    return kr;
}

@implementation NotificationDaemon

- (void)disableDaemon {
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    
    if (!prefs) {
        prefs = [NSMutableDictionary dictionary];
    }
    
    [prefs setObject:@NO forKey:@"enabled"];
    
    BOOL success = [prefs writeToFile:plistPath atomically:YES];
    if (success) {
        NSLog(@"Successfully disabled daemon");
    } else {
        NSLog(@"Failed to update preferences file to disable daemon");
    }
    
    updateStatus(kStatusDisabled);
}

- (void)processNotificationMessage:(NSDictionary *)messageDict {
    NSLog(@"Sending a notification");
    // NSLog(@"Complete messageDict contents: %@", messageDict);

    // get routing data
    NSData *routingKey = messageDict[@"routing_key"];
    NSDictionary *routingData = [db dataForRoutingKey:routingKey];
    
    NSString *bundleID = routingData[@"bundleID"];

    NSString *messageID = messageDict[@"message_id"];

    if (!messageID) {
        return;
    }
    

    NSDictionary *userInfo = nil;

    if ([messageDict[@"is_encrypted"] boolValue]) {
        // our message uses E2EE

        // json or plist
        NSString *outputType =  messageDict[@"data_type"];

        NSData *ciphertext =  messageDict[@"ciphertext"];
        NSData *iv =  messageDict[@"iv"];
        // NSData *tag =  messageDict[@"tag"];
        NSData *decrypted = decryptAESGCM(ciphertext, routingData[@"e2eeKey"], iv, nil);

        if (!decrypted) {
            NSLog(@"Decryption error!");
            ackNotification(messageID, 1); // could not encrypt
            return;
        }

        if ([outputType isEqualToString:@"json"]) {
            NSLog(@"%@", decrypted);
            NSError *error = nil;
            NSDictionary *data = [NSJSONSerialization JSONObjectWithData:decrypted options:0 error:nil];
            if (!data) {
                NSLog(@"Deserialization error of encrypted data: %@", error);
                ackNotification(messageID, 2); // could not deserialize notification
                return;
            }
            userInfo = data;

        } else if ([outputType isEqualToString:@"plist"]) {
            NSError *error = nil;
            NSDictionary *data = [NSPropertyListSerialization propertyListWithData:decrypted
                                                                            options:NSPropertyListImmutable
                                                                            format:nil
                                                                            error:&error];
            if (!data) {
                NSLog(@"Deserialization error of encrypted data: %@", error);
                ackNotification(messageID, 2); // could not deserialize notification
                return;
            }

            
            userInfo = data;
        } else {
            return;
        }
    } else {
        userInfo = messageDict[@"data"];
    }

    NSLog(@"SendPush");
    SendPush(bundleID, userInfo);
    
    ackNotification(messageID, 0); // success
}

- (void)handleWelcomeMessage {
    // login time
    NSString *clientAddress = [self getClientAddress];
    RSA *privKey = getClientPrivKey();
    NSString *language = [[NSLocale preferredLanguages] firstObject];
    startLogin(clientAddress, privKey, language);
}

- (void)authenticationSuccessful {
    updateStatus(kStatusConnected);
}

- (void)checkForRapidDisconnections {
    // Remove disconnection times older than 10 seconds
    NSDate *cutoffTime = [NSDate dateWithTimeIntervalSinceNow:-10.0];
    NSMutableArray *recentDisconnects = [NSMutableArray array];
    
    for (NSDate *disconnectTime in _disconnectionTimes) {
        if ([disconnectTime compare:cutoffTime] == NSOrderedDescending) {
            [recentDisconnects addObject:disconnectTime];
        }
    }
    
    // Update our list to only include recent disconnects
    [_disconnectionTimes removeAllObjects];
    [_disconnectionTimes addObjectsFromArray:recentDisconnects];
    
    // Check if we've had 3 or more disconnects in the last 10 seconds
    if ([_disconnectionTimes count] >= 3) {
        NSLog(@"[WARNING] Detected %lu disconnections within 10 seconds. Disabling daemon.", 
              (unsigned long)[_disconnectionTimes count]);
        
        // Disable the daemon
        [self disableDaemon];
        
        // Exit the daemon process
        exit(-3);
    }
}

- (void)exponentialBackoffConnect {
    NSLog(@"[ExponentialBackoffConnect] Started connection attempts");
    int serverPort;
    int connectionResult;
    int backoff = 1;
    NSString *serverPubKey = [self getServerPubKey];

    updateStatus(kStatusEnabledNotConnected);

    while (1) {
        [self checkForRapidDisconnections];

        serverPort = atoi(serverPortStr);
        NSLog(@"[ExponentialBackoffConnect] Converted server port string to integer: %d", serverPort);

        if (serverPort <= 0) {
            NSLog(@"[ExponentialBackoffConnect] Invalid server port: %d", serverPort);
            updateStatus(kStatusServerConfigBad);
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

        updateStatus(kStatusConnectedNotAuthenticated);

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
        [_disconnectionTimes addObject:[NSDate date]];
        close(connectionResult); // Close the socket before reconnecting
        NSLog(@"[ExponentialBackoffConnect] Socket closed, preparing for next connection attempt.");
        updateStatus(kStatusEnabledNotConnected);
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




- (void)deviceTokenRegistrationCompleted:(NSString *)bundleId {
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
        updateStatus(kStatusEnabledNotConnected);
    }
}

void updateStatus(NSString *status) {
    NSDictionary *statusDict = @{
        @"lastUpdated": [NSDate date],
        @"currentStatus": status
    };
    [statusDict writeToFile:@"/var/mobile/Library/Preferences/com.skyglow.sndp.status.plist" atomically:YES];
    CFNotificationCenterPostNotificationWithOptions(CFNotificationCenterGetDarwinNotifyCenter(),
                                                    CFSTR(kDaemonStatusNewStatus),
                                                    NULL,
                                                    NULL,
                                                    kCFNotificationDeliverImmediately);
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
            updateStatus(kStatusError);
            return -1;
        }

        BOOL isEnabled = [[prefs objectForKey:@"enabled"] boolValue];
        if (!isEnabled) {
            NSLog(@"[Main] Daemon is disabled, aborting");
            updateStatus(kStatusDisabled);
            return 0;
        }

        NSString *profilePlistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
        NSMutableDictionary *profile = [NSMutableDictionary dictionaryWithContentsOfFile:profilePlistPath];

        NotificationDaemon *daemon = [[NotificationDaemon alloc] init];
        [daemon startMonitoringNetworkReachability];

        NSString *serverAddr = profile[@"server_address"];

        if (![serverAddr isKindOfClass:[NSString class]] || serverAddr.length == 0) {
            NSLog(@"[Main] Not registered yet (missing server_address). Staying idle.");
            updateStatus(kStatusConnectedNotAuthenticated /* or a 'NotRegistered' status */);
            CFRunLoopRun(); // or just return 0 if you want it to quit
            return 0;
        }

        serverAddress = serverAddr;
        if ([serverAddress length] > 16) {
            updateStatus(kStatusServerConfigBad);
            return -1;
        }

        NSDictionary *txtRecords = QueryServerLocation([@"_sgn." stringByAppendingString:serverAddr]);

        if (!txtRecords) {
            NSLog(@"Failed to locate server.");
            updateStatus(kStatusError);
            return -1;
        }

        NSString *ip = txtRecords[@"tcp_addr"];
        NSString *port = txtRecords[@"tcp_port"];
        
        db = [[DBManager alloc] init];
        if (db == nil) {
            NSLog(@"Failed to init the DB!");
            updateStatus(kStatusError);
            return -1;
        }

        updateStatus(kStatusEnabledNotConnected);



        if (ip == nil || !isValidIPAddress(ip)) {
            NSLog(@"[Main] Invalid or missing IP address in preferences.");
            updateStatus(kStatusServerConfigBad);
            return -1;
        }

        if (port == nil || !isValidPort(port)) {
            NSLog(@"[Main] Invalid or missing port in preferences.");
            updateStatus(kStatusServerConfigBad);
            return -1;
        }

        if (serverIP) free(serverIP); // Free previously allocated memory if any
        if (serverPortStr) free(serverPortStr); // Free previously allocated memory if any

        serverIP = strdup([ip UTF8String]);
        serverPortStr = strdup([port UTF8String]);

        NSLog(@"[Main] Address and port extracted from preference file: %s,%s", serverIP, serverPortStr);

        // start mach server for tokens
        MachMsgs *machMsgs = [[MachMsgs alloc] init];
        [machMsgs startMachServer];

        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 2, false);

        // Check initial reachability status
        SCNetworkReachabilityFlags flags = [daemon getReachabilityFlags];
        BOOL isReachable = flags & kSCNetworkFlagsReachable;
        BOOL needsConnection = flags & kSCNetworkFlagsConnectionRequired;
        BOOL isReachableWithoutRequiredConnection = isReachable && !needsConnection;

        if (!isReachableWithoutRequiredConnection) {
            NSLog(@"[Main] Initial network check: Network is not reachable, staying dormant.");
            updateStatus(kStatusEnabledNotConnected);
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
