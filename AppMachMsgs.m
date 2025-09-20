#import "AppMachMsgs.h"
#include "Tokens.h"
#include "DBManager.h"

@implementation MachMsgs

- (void)startMachServer {
    kern_return_t kr;
    mach_port_t serverPort;

    self->tokens = [[Tokens alloc] init];

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
        char receiveBuffer[sizeof(MachFeedbackResponce) + 512];
        MachTokenRequestMessage *request = (MachTokenRequestMessage *)receiveBuffer;
        MachTokenResponseMessage response;
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

        // Print debug info about the request
        NSLog(@"Request from port: %d to port: %d with ID: %d",
              request->header.msgh_remote_port,
              request->header.msgh_local_port,
              request->header.msgh_id);

        

        NSLog(@"Processing request of type %d", request->type);

        if (request->type == SKYGLOW_REQUEST_TOKEN) {
            // Only check remote port for requests that expect a response
            if (request->header.msgh_remote_port == MACH_PORT_NULL) {
                NSLog(@"Request has an invalid remote port, cannot send response");
                continue;
            }

            // Set up response with proper complex message bits
            response.header.msgh_bits = MACH_MSGH_BITS(
                MACH_MSG_TYPE_COPY_SEND,     // remote port right
                0                           // no local port
            ) | MACH_MSGH_BITS_COMPLEX;      // indicate complex message

            response.header.msgh_size = sizeof(MachTokenResponseMessage);
            response.header.msgh_remote_port = request->header.msgh_remote_port;
            response.header.msgh_local_port = MACH_PORT_NULL;
            response.header.msgh_id = request->header.msgh_id + 100;

            // Initialize body descriptor
            response.body.msgh_descriptor_count = 0;

            NSString *bundleID = [NSString stringWithUTF8String:request->bundleID];
            NSError *error = nil;
            NSData *tokenData = [self->tokens getDeviceToken:bundleID error:error];
            
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

            NSLog(@"Sending response of size %lu to port %d", sizeof(response), response.header.msgh_remote_port);
        
            kr = mach_msg(&response.header, MACH_SEND_MSG, sizeof(response), 0, 
                     MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
            if (kr != KERN_SUCCESS) {
                NSLog(@"Error sending mach response: %s (error code: %d)", mach_error_string(kr), kr);
            } else {
                NSLog(@"Successfully sent response for bundle ID: %s", request->bundleID);
            }
        } else if (request->type == SKYGLOW_FEEDBACK_DATA) {
            MachFeedbackResponce *feedback = (MachFeedbackResponce *)request;
            NSLog(@"Received feedback for topic: %s, reason: %s", feedback->topic, feedback->reason);
            [self->tokens removeDeviceTokenForBundleId:[NSString stringWithUTF8String:feedback->topic] 
                                              reason:[NSString stringWithUTF8String:feedback->reason]];
        } else {
            NSLog(@"Unknown request type: %d", request->type);
            response.type = SKYGLOW_ERROR;
            response.tokenLength = 0;
            strcpy(response.error, "Unknown request type");
        }
        
    }
}

@end