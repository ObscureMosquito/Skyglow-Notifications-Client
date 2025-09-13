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

// Local safe string copy (always NUL-terminates when size > 0)
static size_t sg_strlcpy(char *dst, const char *src, size_t size) {
    if (!dst || !src) return 0;
    size_t n = 0;
    if (size) {
        while (n + 1 < size && src[n]) {
            dst[n] = src[n];
            n++;
        }
        dst[n] = '\0';
    }
    while (src[n]) n++; // finish counting
    return n;
}

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

    // Safe copy topic (bounded)
    size_t tLen = sg_strlcpy(msg.topic,
                             (const char *)topicData.bytes,
                             sizeof(msg.topic));
    if (tLen >= sizeof(msg.topic)) {
        NSLog(@"[SendPush] Topic truncated (%zu >= %zu): %@",
              tLen, sizeof(msg.topic), topic);
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

- (void)deviceTokenRegistrationCompleted:(NSString *)bundleId {
    if ([bundleId isEqualToString:_pendingBundleID]) {
        _tokenRegistrationCompleted = YES;
        dispatch_semaphore_signal(_tokenRegistrationSemaphore);
    }
}

- (NSData*)getDeviceToken:(NSString*)bundleID error:(NSError*)err { 
    NSArray *previousTokens = [db dataForBundleID:bundleID];
    if ([previousTokens count] == 0) {
        return [self generateDeviceToken:bundleID error:err];
    } else {
        return previousTokens[0][@"token"];
    }
}

- (NSData*)generateDeviceToken:(NSString*)bundleID error:(NSError*)err {
    NSLog(@"Generating Device Token");
    // Securely generate 16 bytes, (K in protocol)
    uint8_t K[16];
    int status = SecRandomCopyBytes(kSecRandomDefault, (sizeof K)/(sizeof K[0]), K);
    if (status != errSecSuccess) {
        err = [NSError errorWithDomain:@"Failed to generate secure secret!" code:1 userInfo:nil];
        return nil;
    }

    // create routing key
    unsigned char hashedValueChar[32];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, K, 16);
    SHA256_Final(hashedValueChar, &sha256);
    CC_SHA256(K, 16, hashedValueChar);    
    NSData *routingKey = [NSData dataWithBytes:hashedValueChar length:32];
    
    // create e2ee key
    NSString *hkdfSalt = [NSString stringWithFormat:@"%@%@", serverAddress, @"Hello from the Skyglow Notifications developers!"];
    NSData *keyMaterial = [NSData dataWithBytes:K length:sizeof(K)];
    NSData *e2eeKey = deriveE2EEKey(keyMaterial, hkdfSalt, 32);

    // create final device token
    NSData *serverAddrData = [serverAddress dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *paddedServerAddr = [NSMutableData dataWithCapacity:16];
    
    if (serverAddrData.length < 16) {
        // If server address is less than 16 bytes, add padding
        [paddedServerAddr appendData:serverAddrData];
        NSUInteger paddingNeeded = 16 - serverAddrData.length;
        uint8_t zeroPadding[paddingNeeded];
        memset(zeroPadding, 0, paddingNeeded); // Using zero as padding
        [paddedServerAddr appendBytes:zeroPadding length:paddingNeeded];
    } else if (serverAddrData.length > 16) {
        // smth has gone critially wrong.
        [paddedServerAddr appendBytes:[serverAddrData bytes] length:16];
    } else {
        // exactly 16 bytes
        [paddedServerAddr appendData:serverAddrData];
    }
    
    // Combine padded server address with K to ensure we have a 32-byte key
    NSMutableData *deviceKey = [NSMutableData dataWithData:paddedServerAddr];
    [deviceKey appendBytes:K length:16];

     // send to server
    BOOL didSucceed = registerDeviceToken(routingKey, bundleID);

    if (didSucceed == NO) {
        NSLog(@"Timeout waiting for token registration acknowledgment");
        err = [NSError errorWithDomain:@"Token registration acknowledgment timeout" code:3 userInfo:nil];
        return nil;
    }

    // store our key
    BOOL result = [db storeTokenData:routingKey e2eeKey:e2eeKey bundleID:bundleID token:deviceKey];
    if (!result) {
        err = [NSError errorWithDomain:@"Failed to store created token!" code:2 userInfo:nil];
        return nil;
    }
    
    return deviceKey;
}

- (void)handleWelcomeMessage {
    // login time
    NSString *clientAddress = [self getClientAddress];
    RSA *privKey = [self getClientPrivKey];
    NSString *language = [[NSLocale preferredLanguages] firstObject];
    startLogin(clientAddress, privKey, language);
}

- (void)authenticationSuccessful {
    updateStatus(kStatusConnected);
}

- (void)exponentialBackoffConnect {
    NSLog(@"[ExponentialBackoffConnect] Started connection attempts");
    int serverPort;
    int connectionResult;
    int backoff = 1;
    NSString *serverPubKey = [self getServerPubKey];

    updateStatus(kStatusEnabledNotConnected);

    while (1) {
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

- (void)startMachServer {
    kern_return_t kr;
    mach_port_t serverPort;

    // Create a mach port for our service
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &serverPort);
    if (kr != KERN_SUCCESS) {
        NSLog(@"Failed to allocate mach port: %s", mach_error_string(kr));
        return;
    }

    // Insert a send right
    kr = mach_port_insert_right(mach_task_self(), serverPort, serverPort, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        NSLog(@"Failed to insert send right: %s", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), serverPort);
        return;
    }

    // Register the service
    kr = bootstrap_register(bootstrap_port, SKYGLOW_MACH_SERVICE_NAME_TOKEN, serverPort);
    if (kr != KERN_SUCCESS) {
        NSLog(@"Failed to register mach service: %s", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), serverPort);
        return;
    }

    NSLog(@"Successfully registered mach service: %s", SKYGLOW_MACH_SERVICE_NAME_TOKEN);

    // Start a thread to listen for messages
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self handleMachMessages:serverPort];
    });
}

// chatgpt :sob:
- (void)handleMachMessages:(mach_port_t)serverPort {
    while (1) {
        // Use a buffer large enough for the MachRequestMessage structure plus extra space
        char receiveBuffer[sizeof(MachRequestMessage) + 512];
        MachRequestMessage *request = (MachRequestMessage *)receiveBuffer;
        MachResponseMessage response;
        kern_return_t kr;
        
        // Zero out the buffers
        memset(receiveBuffer, 0, sizeof(receiveBuffer));
        memset(&response, 0, sizeof(response));
        
        // Initialize header with the local port
        request->header.msgh_local_port = serverPort;
        
        // Receive the message directly
        kr = mach_msg(&request->header, MACH_RCV_MSG, 0, sizeof(receiveBuffer), 
                     serverPort, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        
        if (kr != KERN_SUCCESS) {
            NSLog(@"Error receiving mach message: %s (error code: %d)", 
                 mach_error_string(kr), kr);
                 
            // If message is too large, try to receive and discard it to avoid getting stuck
            if (kr == MACH_RCV_TOO_LARGE) {
                NSLog(@"Message size exceeded buffer capacity.");
                mach_msg_header_t header;
                mach_msg(&header, MACH_RCV_MSG | MACH_RCV_LARGE, 0, 0, 
                       serverPort, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
            }
            continue;
        }
        
        // Check if we got a valid bundle ID
        if (request->bundleID[0] == '\0') {
            NSLog(@"Received message with empty bundle ID, ignoring");
            continue;
        }
        
        NSLog(@"Received token request for bundle ID: %s (message size: %d)", 
              request->bundleID, request->header.msgh_size);
        
        // Check if the remote port is valid
        if (request->header.msgh_remote_port == MACH_PORT_NULL) {
            NSLog(@"Request has an invalid remote port, cannot send response");
            continue;
        }
        
        // Print debug info about the request
        NSLog(@"Request from port: %d to port: %d with ID: %d",
              request->header.msgh_remote_port,
              request->header.msgh_local_port,
              request->header.msgh_id);
        
        // Set up response with proper complex message bits
        // Replace MACH_MSGH_BITS_SET with MACH_MSGH_BITS
        response.header.msgh_bits = MACH_MSGH_BITS(
            MACH_MSG_TYPE_COPY_SEND,     // remote port right
            0                           // no local port
        ) | MACH_MSGH_BITS_COMPLEX;      // indicate complex message
        
        response.header.msgh_size = sizeof(MachResponseMessage);
        response.header.msgh_remote_port = request->header.msgh_remote_port;
        response.header.msgh_local_port = MACH_PORT_NULL;
        response.header.msgh_id = request->header.msgh_id + 100;
        
        // Initialize body descriptor
        response.body.msgh_descriptor_count = 0;
        
        NSLog(@"Processing request of type %d", request->type);
        
        if (request->type == SKYGLOW_REQUEST_TOKEN) {
            NSString *bundleID = [NSString stringWithUTF8String:request->bundleID];
            NSError *error = nil;
            NSData *tokenData = [self getDeviceToken:bundleID error:error];
            
            if (tokenData && tokenData.length > 0) {
                NSLog(@"Generated token for %@, length: %lu", bundleID, (unsigned long)tokenData.length);
                response.type = SKYGLOW_RESPONSE_TOKEN;
                response.tokenLength = (uint32_t)MIN(tokenData.length, SKYGLOW_MAX_TOKEN_SIZE);
                memcpy(response.tokenData, [tokenData bytes], response.tokenLength);
                strcpy(response.error, "");
            } else {
                NSLog(@"Failed to generate token for %@", bundleID);
                response.type = SKYGLOW_ERROR;
                response.tokenLength = 0;
                if (error) {
                    strcpy(response.error, [[error localizedDescription] UTF8String]);
                } else {
                    strcpy(response.error, "Unknown error generating device token");
                }
            }
        } else {
            NSLog(@"Unknown request type: %d", request->type);
            response.type = SKYGLOW_ERROR;
            response.tokenLength = 0;
            strcpy(response.error, "Unknown request type");
        }
        
        NSLog(@"Sending response of size %lu to port %d", sizeof(response), response.header.msgh_remote_port);
        
        // Send response
        kr = mach_msg(&response.header, MACH_SEND_MSG, sizeof(response), 0, 
                     MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            NSLog(@"Error sending mach response: %s (error code: %d)", mach_error_string(kr), kr);
        } else {
            NSLog(@"Successfully sent response for bundle ID: %s", request->bundleID);
        }
    }
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

        NSString *profilePlistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
        NSMutableDictionary *profile = [NSMutableDictionary dictionaryWithContentsOfFile:profilePlistPath];
        

        NotificationDaemon *daemon = [[NotificationDaemon alloc] init];
        [daemon startMachServer];
        [daemon startMonitoringNetworkReachability];

        serverAddress = [profile objectForKey:@"server_address"];
        if ([serverAddress length] > 16) {
            updateStatus(kStatusServerConfigBad);
            return -1;
        }
        
        NSDictionary *txtRecords = QueryServerLocation([@"_sgn." stringByAppendingString:[profile objectForKey:@"server_address"]]);

        if (!txtRecords) {
            NSLog(@"Failed to locate server.");
            updateStatus(kStatusError);
            return -1;
        }

        NSString *ip = txtRecords[@"tcp_addr"];
        NSString *port = txtRecords[@"tcp_port"];
        BOOL isEnabled = [[prefs objectForKey:@"enabled"] boolValue];

        db = [[DBManager alloc] init];
        if (db == nil) {
            NSLog(@"Failed to init the DB!");
            updateStatus(kStatusError);
            return -1;
        }
        
        if (!isEnabled) {
            NSLog(@"[Main] Daemon is disabled, aborting");
            updateStatus(kStatusDisabled);
            return 0;
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
