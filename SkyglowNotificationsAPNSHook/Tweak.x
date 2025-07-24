#import "../TweakMachMessages.h"
#include <bootstrap.h>

static NSData *requestDeviceTokenFromDaemon(NSString *bundleID) {
    mach_port_t clientPort;
    mach_port_t serverPort;
    kern_return_t kr;
    
    // Create a port for receiving the reply with proper rights
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &clientPort);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[Skyglow APNS Hook] Failed to allocate client port: %s", mach_error_string(kr));
        return nil;
    }
    
    // Add send right to our receive right
    kr = mach_port_insert_right(mach_task_self(), clientPort, clientPort, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[Skyglow APNS Hook] Failed to insert send right: %s", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), clientPort);
        return nil;
    }
    
    // Look up the server port
    kr = bootstrap_look_up(bootstrap_port, SKYGLOW_MACH_SERVICE_NAME, &serverPort);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[Skyglow APNS Hook] Failed to look up service %s: %s", 
              SKYGLOW_MACH_SERVICE_NAME, mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), clientPort);
        return nil;
    }
    
    // Print debug information about the ports
    NSLog(@"[Skyglow APNS Hook] Client port: %d, Server port: %d", clientPort, serverPort);
    
    // Prepare request message
    MachRequestMessage request;
    bzero(&request, sizeof(request));
    
    // Set up the request - use correct bits for RPC style
    request.header.msgh_bits = MACH_MSGH_BITS(
        MACH_MSG_TYPE_COPY_SEND,    // remote port right
        MACH_MSG_TYPE_MAKE_SEND     // local port right
    ) | MACH_MSGH_BITS_COMPLEX;     // indicate complex message
    
    request.header.msgh_size = sizeof(MachRequestMessage);
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
    
    NSLog(@"[Skyglow APNS Hook] Sending token request for bundle ID: %s", request.bundleID);
    
    // Send the request
    kr = mach_msg(&request.header, MACH_SEND_MSG, sizeof(request), 0, 
                  MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[Skyglow APNS Hook] Failed to send message: %s", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), serverPort);
        mach_port_deallocate(mach_task_self(), clientPort);
        return nil;
    }
    
    NSLog(@"[Skyglow APNS Hook] Message sent successfully, waiting for response");
    
    // Use a larger buffer for receiving
    // Add extra space to handle any potential message size issues
    char receiveBuffer[sizeof(MachResponseMessage) + 512];
    MachResponseMessage *response = (MachResponseMessage *)receiveBuffer;
    
    // Zero out the buffer
    memset(receiveBuffer, 0, sizeof(receiveBuffer));
    
    // Set up the receive parameters
    response->header.msgh_local_port = clientPort;
    
    // Use a timeout to avoid hanging indefinitely
    mach_msg_timeout_t timeout = 5000; // 5 seconds
    
    NSLog(@"[Skyglow APNS Hook] Waiting for response with buffer size: %lu", sizeof(receiveBuffer));
    
    // Receive the response with timeout
    kr = mach_msg(&response->header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(receiveBuffer), 
                  clientPort, timeout, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[Skyglow APNS Hook] Failed to receive response: %s (error code: %d)", 
             mach_error_string(kr), kr);
        mach_port_deallocate(mach_task_self(), serverPort);
        mach_port_deallocate(mach_task_self(), clientPort);
        return nil;
    }
    
    NSLog(@"[Skyglow APNS Hook] Received response of type: %d, size: %d", 
         response->type, response->header.msgh_size);
    
    // Clean up ports
    mach_port_deallocate(mach_task_self(), serverPort);
    mach_port_deallocate(mach_task_self(), clientPort);
    
    // Process response
    if (response->type == SKYGLOW_RESPONSE_TOKEN && response->tokenLength > 0) {
        NSLog(@"[Skyglow APNS Hook] Received token from daemon, length: %u", response->tokenLength);
        return [NSData dataWithBytes:response->tokenData length:response->tokenLength];
    } else {
        NSLog(@"[Skyglow APNS Hook] Error receiving token: %s", response->error);
        return nil;
    }
}

%hook UIApplication

// iOS 7 & below
- (void)registerForRemoteNotificationTypes:(UIRemoteNotificationType)types {
    NSLog(@"[Skyglow APNS Hook] Intercepted registerForRemoteNotificationTypes: %lu", (unsigned long)types);
    
    // Get bundle ID of the current application
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
    
    // Make the request asynchronous to avoid blocking the main thread
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Request device token from daemon on background thread
        NSData *deviceToken = requestDeviceTokenFromDaemon(bundleID);
        dispatch_async(dispatch_get_main_queue(), ^{
            // Find the app delegate
            id<UIApplicationDelegate> delegate = [UIApplication sharedApplication].delegate;
                    
            if (deviceToken) {
                    // Call the delegate method if it implements it
                    if ([delegate respondsToSelector:@selector(application:didRegisterForRemoteNotificationsWithDeviceToken:)]) {
                        [delegate application:[UIApplication sharedApplication] didRegisterForRemoteNotificationsWithDeviceToken:deviceToken];
                        NSLog(@"[Skyglow APNS Hook] Sent device token to app");
                    }
                
            } else {
                // Fallback on main thread
                dispatch_async(dispatch_get_main_queue(), ^{
                    NSLog(@"[Skyglow APNS Hook] Failed to get token from daemon!");
                    if ([delegate respondsToSelector:@selector(application:didFailToRegisterForRemoteNotificationsWithError:)]) {
                        [delegate application:[UIApplication sharedApplication] didFailToRegisterForRemoteNotificationsWithError:[NSError errorWithDomain:@"token stuff failed. oops :(" code:0 userInfo:nil]];
                    }
                });
            }
        });
    });
}

%end