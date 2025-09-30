#import <mach/mach.h>
#include <bootstrap.h>
#import "TweakMachMessages.h"
#import <objc/runtime.h>
#import <objc/message.h>

static mach_port_t gSkyglowPort = MACH_PORT_NULL;

@interface APSIncomingMessage : NSObject
+ (instancetype)initWithTopic:(id)arg1 userInfo:(id)arg2;
@end


@interface SBRemoteNotificationServer : NSObject
+ (instancetype)sharedInstance;
- (void)connection:(id)arg1 didReceiveIncomingMessage:(id)arg2;
@end


@interface SBApplicationUninstallationOperation : NSObject
{
    NSString *_bundleIdentifier;
}
@end


static void SendNotification(NSString *topic, NSDictionary *userInfo) {
    APSIncomingMessage *messageObj = [[%c(APSIncomingMessage) alloc] initWithTopic:topic userInfo:userInfo];
    [[%c(SBRemoteNotificationServer) sharedInstance] connection:nil didReceiveIncomingMessage:messageObj];
}



static void HandlePush(MachPushRequestMessage *req) {
	NSLog(@"[SGN Springboard] HandlePush");
    NSString *topic = [NSString stringWithUTF8String:req->topic] ?: @"";
    NSDictionary *userInfo = nil;
    if (req->userInfoLength > 0 && req->userInfoLength <= SKYGLOW_MAX_USERINFO_SIZE) {
        NSData *data = [NSData dataWithBytes:req->userInfoData length:req->userInfoLength];
        userInfo = [NSPropertyListSerialization propertyListWithData:data
                                                             options:NSPropertyListMutableContainersAndLeaves
                                                              format:NULL
                                                               error:NULL];
        if (![userInfo isKindOfClass:[NSDictionary class]]) {
            userInfo = nil;
        }
    }
    SendNotification(topic, userInfo ?: @{});
}

static void MachServerLoop() {
    while (1) {
        MachPushRequestMessage req;
        memset(&req, 0, sizeof(req));
        kern_return_t kr = mach_msg(&req.header,
                                    MACH_RCV_MSG,
                                    0,
                                    sizeof(req),
                                    gSkyglowPort,
                                    MACH_MSG_TIMEOUT_NONE,
                                    MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) continue;
        if (req.type == SKYGLOW_REQUEST_PUSH) {
            HandlePush(&req);
        }
    }
}

// Uninstall feedback trigger
%hook SBApplicationUninstallationOperation
-(void)main {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *bundleId = [self valueForKey:@"_bundleIdentifier"];
        NSLog(@"[SGN Springboard] App is being uninstalled! %@", bundleId);
        // Send bundleId to all clients
        if (bundleId) {
            // Convert topic to UTF8 once (fail if cannot be represented)
            NSData *topicData = [bundleId dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
            if (!topicData || topicData.length == 0) {
                NSLog(@"[SendFeedback] Topic UTF8 conversion failed");
                return;
            }

            NSString *reason = @"App uninstalled";
            NSData *reasonData = [reason dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];

            mach_port_t bootstrapPort = MACH_PORT_NULL;
            kern_return_t kr = task_get_bootstrap_port(mach_task_self(), &bootstrapPort);
            if (kr != KERN_SUCCESS || bootstrapPort == MACH_PORT_NULL) {
                NSLog(@"[SendFeedback] task_get_bootstrap_port: %s", mach_error_string(kr));
                return;
            }

            mach_port_t servicePort = MACH_PORT_NULL;
            kr = bootstrap_look_up(bootstrapPort, SKYGLOW_MACH_SERVICE_NAME_TOKEN, &servicePort);
            if (kr != KERN_SUCCESS || servicePort == MACH_PORT_NULL) {
                NSLog(@"[SendFeedback] bootstrap_look_up(%s): %s",
                    SKYGLOW_MACH_SERVICE_NAME_TOKEN, mach_error_string(kr));
                return;
            }

            MachFeedbackResponce msg;
            memset(&msg, 0, sizeof(msg));

            msg.header.msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
            msg.header.msgh_remote_port = servicePort;
            msg.header.msgh_id          = SKYGLOW_FEEDBACK_DATA;
            msg.body.msgh_descriptor_count = 0;
            msg.type = SKYGLOW_FEEDBACK_DATA;

            // topic
            size_t maxTopic = sizeof(msg.topic) - 1;
            size_t copyLen = MIN((size_t)topicData.length, maxTopic);
            memcpy(msg.topic, topicData.bytes, copyLen);
            msg.topic[copyLen] = '\0';
            if (copyLen < topicData.length) {
                NSLog(@"[SendFeedback] Feedback Topic truncated (%zu > %zu): %@",
                    (size_t)topicData.length, maxTopic, bundleId);
            }

            // reason i hope
            size_t maxReason = sizeof(msg.reason) - 1;
            copyLen = MIN((size_t)reasonData.length, maxReason);
            memcpy(msg.reason, reasonData.bytes, copyLen);
            msg.reason[copyLen] = '\0';
            if (copyLen < reasonData.length) {
                NSLog(@"[SendFeedback] Feedback Reason truncated (%zu > %zu): %@",
                    (size_t)reasonData.length, maxReason, reason);
            }

            size_t usedSize = sizeof(MachFeedbackResponce);
            // 4-byte align
            usedSize = (usedSize + 3) & ~(size_t)3;

            if (usedSize > sizeof(msg) || usedSize > UINT32_MAX) {
                NSLog(@"[SendFeedback] Internal size computation invalid (%zu)", usedSize);
                return;
            }
            msg.header.msgh_size = (mach_msg_size_t)usedSize;

            NSLog(@"[SendFeedback] topic='%@' totalMsgSize=%u",
                bundleId, msg.header.msgh_size);

            kr = mach_msg(&msg.header,
                        MACH_SEND_MSG,
                        msg.header.msgh_size,
                        0,
                        MACH_PORT_NULL,
                        MACH_MSG_TIMEOUT_NONE,
                        MACH_PORT_NULL);
            if (kr != KERN_SUCCESS) {
                NSLog(@"[SendFeedback] mach_msg send failed: %s (%d)",
                    mach_error_string(kr), kr);
            }
            return;
        }
    });
    %orig;
}
%end

static NSData *requestDeviceTokenFromDaemon(NSString *bundleID) {
    mach_port_t clientPort;
    mach_port_t serverPort;
    kern_return_t kr;
    
    // Create a port for receiving the reply with proper rights
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &clientPort);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[Skyglow Springboard] Failed to allocate client port: %s", mach_error_string(kr));
        return nil;
    }
    
    // Add send right to our receive right
    kr = mach_port_insert_right(mach_task_self(), clientPort, clientPort, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[Skyglow Springboard] Failed to insert send right: %s", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), clientPort);
        return nil;
    }
    
    // Look up the server port
    kr = bootstrap_look_up(bootstrap_port, SKYGLOW_MACH_SERVICE_NAME_TOKEN, &serverPort);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[Skyglow Springboard] Failed to look up service %s: %s", 
              SKYGLOW_MACH_SERVICE_NAME_TOKEN, mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), clientPort);
        return nil;
    }
    
    // Print debug information about the ports
    NSLog(@"[Skyglow Springboard] Client port: %d, Server port: %d", clientPort, serverPort);
    
    // Prepare request message
    MachTokenRequestMessage request;
    bzero(&request, sizeof(request));
    
    // Set up the request - use correct bits for RPC style
    request.header.msgh_bits = MACH_MSGH_BITS(
        MACH_MSG_TYPE_COPY_SEND,    // remote port right
        MACH_MSG_TYPE_MAKE_SEND     // local port right
    ) | MACH_MSGH_BITS_COMPLEX;     // indicate complex message
    
    request.header.msgh_size = sizeof(MachTokenRequestMessage);
    request.header.msgh_remote_port = serverPort;
    request.header.msgh_local_port = clientPort;
    request.header.msgh_id = 100;
    
    // Initialize body descriptor
    request.body.msgh_descriptor_count = 0;
    
    request.type = SKYGLOW_REQUEST_TOKEN;
    
    // Copy bundle ID safely
    const char *bundleIDStr = [bundleID UTF8String];
    strncpy(request.bundleID, bundleIDStr, sizeof(request.bundleID) - 1);
    request.bundleID[sizeof(request.bundleID) - 1] = '\0';
    
    NSLog(@"[Skyglow Springboard] Sending token request for bundle ID: %s", request.bundleID);
    
    // Send the request
    kr = mach_msg(&request.header, MACH_SEND_MSG, sizeof(request), 0, 
                  MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[Skyglow Springboard] Failed to send message: %s", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), serverPort);
        mach_port_deallocate(mach_task_self(), clientPort);
        return nil;
    }
    
    NSLog(@"[Skyglow Springboard] Message sent successfully, waiting for response");
    
    // Use a larger buffer for receiving
    char receiveBuffer[sizeof(MachTokenResponseMessage) + 512];
    MachTokenResponseMessage *response = (MachTokenResponseMessage *)receiveBuffer;
    
    // Zero out the buffer
    memset(receiveBuffer, 0, sizeof(receiveBuffer));
    
    // Set up the receive parameters
    response->header.msgh_local_port = clientPort;
    
    // Use a timeout to avoid hanging indefinitely
    mach_msg_timeout_t timeout = 20000; // 20 seconds
    
    NSLog(@"[Skyglow Springboard] Waiting for response with buffer size: %lu", sizeof(receiveBuffer));
    
    // Receive the response with timeout
    kr = mach_msg(&response->header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(receiveBuffer), 
                  clientPort, timeout, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[Skyglow Springboard] Failed to receive response: %s (error code: %d)", 
             mach_error_string(kr), kr);
        mach_port_deallocate(mach_task_self(), serverPort);
        mach_port_deallocate(mach_task_self(), clientPort);
        return nil;
    }
    
    NSLog(@"[Skyglow Springboard] Received response of type: %d, size: %d", 
         response->type, response->header.msgh_size);
    
    // Clean up ports
    mach_port_deallocate(mach_task_self(), serverPort);
    mach_port_deallocate(mach_task_self(), clientPort);
    
    // Process response
    if (response->type == SKYGLOW_RESPONSE_TOKEN && response->tokenLength > 0) {
        NSLog(@"[Skyglow Springboard] Received token from daemon, length: %u", response->tokenLength);
        return [NSData dataWithBytes:response->tokenData length:response->tokenLength];
    } else {
        NSLog(@"[Skyglow Springboard] Error receiving token: %s", response->error);
        return nil;
    }
}

// Needed to recreate the register function
@interface SBRemoteNotificationClient : NSObject
- (instancetype)initWithBundleIdentifier:(NSString *)bundleIdentifier;
- (void)setEnvironment:(id)environment;
- (id)environment;
- (int)appEnabledTypes;
- (void)setAppEnabledTypes:(int)types;
- (int)settingsPresentedTypes;
- (void)setSettingsPresentedTypes:(int)types;
- (void)setLastKnownDeviceToken:(NSData *)token;
@end

@interface SBRemoteApplication : NSObject
- (void)remoteNotificationRegistrationSucceededWithDeviceToken:(NSData *)deviceToken;
@end

@interface UIApplication (Private)
- (BOOL)isSystemApplication;
- (BOOL)isInternalApplication;
- (NSString *)bundleIdentifier;
- (SBRemoteApplication *)remoteApplication;
@end

@interface SBApplicationPersistence : NSObject
+ (instancetype)sharedInstance;
- (void)setArchivedObject:(id)object forKey:(NSString *)key bundleOrDisplayIdentifier:(NSString *)identifier;
@end

@interface SBPushStore : NSObject
+ (instancetype)sharedInstance;
- (void)updatePushStores;
@end

@interface SBRemoteNotificationPermissionAlert : NSObject
- (instancetype)initWithApplication:(id)application notificationTypes:(int)types;
@end

@interface SBAlertItemsController : NSObject
+ (instancetype)sharedInstance;
- (void)deactivateAlertItemsOfClass:(Class)alertClass;
- (void)activateAlertItem:(id)alert;
@end

%hook SBRemoteNotificationServer

// This function was decompiled by AI, but i've modified it to use my fun things :)
- (int)registerApplication:(id)application forEnvironment:(id)environment withTypes:(int)notificationTypes {
    NSLog(@"[SGN Springboard] registerApplication:%@ forEnvironment:%@ withTypes:%d", [application bundleIdentifier], environment, notificationTypes);
    
    BOOL needsUpdate = NO;
    
    NSString *bundleIdentifier = [application bundleIdentifier];
    
    NSMutableDictionary *bundleIdentifiersToClients = [self valueForKey:@"_bundleIdentifiersToClients"];
    SBRemoteNotificationClient *client = [bundleIdentifiersToClients objectForKey:bundleIdentifier];
    
    if (client == nil) {
        // Create new client if it doesn't exist

        client = [[%c(SBRemoteNotificationClient) alloc] initWithBundleIdentifier:bundleIdentifier];
        [bundleIdentifiersToClients setObject:client forKey:bundleIdentifier];

        needsUpdate = YES;
        
        NSLog(@"[SGN Springboard] Created new notification client for %@", bundleIdentifier);
    }
    
    // Check if environment needs to be updated
    if (![[client environment] isEqual:environment]) {
        [client setEnvironment:environment];
        needsUpdate = YES;
    }
    
    // Check if notification types need to be updated
    int appEnabledTypes = [client appEnabledTypes];
    int requestedTypes = notificationTypes & 0xF; // Mask to lower 4 bits

    if (appEnabledTypes != requestedTypes) {
        [client setAppEnabledTypes:requestedTypes];
        needsUpdate = YES;
    }
    
    // Handle connection and identity verification
    NSMutableDictionary *environmentsToConnections = [self valueForKey:@"_environmentsToConnections"];
    id connection = [environmentsToConnections objectForKey:environment];
    
    if (connection == nil) {
        [self performSelector:@selector(calculateTopics)];
        connection = [environmentsToConnections objectForKey:environment];
    }
    
    id validConnection = nil;
    if (connection != nil && [connection respondsToSelector:@selector(hasIdentity)] && [connection performSelector:@selector(hasIdentity)]) {
        validConnection = connection;
    }
    
    // Handle permission alerts for new notification types
    int settingsPresentedTypes = [client settingsPresentedTypes];
    
    if ((notificationTypes & 0x8) != 0 && (settingsPresentedTypes & 0x8) == 0) {
        // Show remote notification permission alert
        int alertTypes = (requestedTypes != 0x8) ? 0xF : 0x8;
        SBRemoteNotificationPermissionAlert *alert = [[%c(SBRemoteNotificationPermissionAlert) alloc] initWithApplication:application notificationTypes:alertTypes];
        
        if (alert != nil) {
            SBAlertItemsController *alertController = [%c(SBAlertItemsController) sharedInstance];
            [alertController deactivateAlertItemsOfClass:[%c(SBRemoteNotificationPermissionAlert) class]];
            [alertController activateAlertItem:alert];
            [client setSettingsPresentedTypes:settingsPresentedTypes | requestedTypes];
        }
    } else if ((notificationTypes & ~settingsPresentedTypes & 0x7) != 0) {
        // Show permission alert for other types
        SBRemoteNotificationPermissionAlert *alert = [[%c(SBRemoteNotificationPermissionAlert) alloc] initWithApplication:application notificationTypes:0x7];
        if (alert != nil) {
            SBAlertItemsController *alertController = [%c(SBAlertItemsController) sharedInstance];
            [alertController deactivateAlertItemsOfClass:[%c(SBRemoteNotificationPermissionAlert) class]];
            [alertController activateAlertItem:alert];
            [client setSettingsPresentedTypes:settingsPresentedTypes | requestedTypes];
        }
    }
    
    // check if we wanna use skyglow or apns
    NSData *publicToken = nil;
    if (validConnection != nil) {
        // APNS
        // publicToken = [validConnection performSelector:@selector(publicToken)];
        publicToken = nil; // i dont wanna deal with hell rn
    }
    
    publicToken = requestDeviceTokenFromDaemon(bundleIdentifier);
    

    
    if (publicToken != nil) {
        NSLog(@"[SGN Springboard] Providing token to %@", bundleIdentifier);
        if ([application respondsToSelector:@selector(remoteApplication)]) {
            SBRemoteApplication *remoteApp = [application remoteApplication];
            if ([remoteApp respondsToSelector:@selector(remoteNotificationRegistrationSucceededWithDeviceToken:)]) {
                [remoteApp remoteNotificationRegistrationSucceededWithDeviceToken:publicToken];
            }
        }
        [client setLastKnownDeviceToken:publicToken];
    } else {
        NSLog(@"[SGN Springboard] No token available for %@", bundleIdentifier);
    }

    
    // Persist changes and update topics if needed
    if (needsUpdate) {
        [[%c(SBApplicationPersistence) sharedInstance] setArchivedObject:client forKey:@"SBRemoteNotificationClient" bundleOrDisplayIdentifier:bundleIdentifier];
        [self performSelector:@selector(calculateTopics)];
    }
    
    return needsUpdate;
}

%end



%ctor {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &gSkyglowPort);
        if (kr != KERN_SUCCESS) return;
        kr = mach_port_insert_right(mach_task_self(), gSkyglowPort, gSkyglowPort, MACH_MSG_TYPE_MAKE_SEND);
        if (kr != KERN_SUCCESS) return;
        mach_port_t bootstrapPort = MACH_PORT_NULL;
        task_get_bootstrap_port(mach_task_self(), &bootstrapPort);
        bootstrap_register(bootstrapPort, SKYGLOW_MACH_SERVICE_NAME_PUSH, gSkyglowPort); // todo fix
        MachServerLoop();
    });
}
