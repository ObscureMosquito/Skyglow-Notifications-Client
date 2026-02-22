/*
 * sgn_test_token.m — request a Skyglow device token from the daemon
 *
 * Compile on device:
 *   clang -fobjc-arc -framework Foundation sgn_test_token.m -o sgn_test_token
 *
 * Usage:
 *   ./sgn_test_token <bundle_id>
 *   ./sgn_test_token com.apple.weather
 *
 * Triggers the full C_REG_TOKEN flow and prints the hex token on success.
 * The daemon stores the token locally and uploads it to the server.
 * Use the routing key (SHA-256 of token bytes 16-31) to send a test push.
 */

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <bootstrap.h>

#define SKYGLOW_MACH_SERVICE_NAME_TOKEN "com.skyglow.sgn.token"
#define SKYGLOW_MAX_TOKEN_SIZE 32

#pragma pack(4)
typedef enum {
    SKYGLOW_REQUEST_TOKEN = 1,
    SKYGLOW_RESPONSE_TOKEN = 2,
    SKYGLOW_ERROR = 3,
} MachMessageType;

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t   body;
    MachMessageType   type;
    char              bundleID[256];
    uint8_t           padding[4];
} MachTokenRequestMessage;

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t   body;
    MachMessageType   type;
    uint32_t          tokenLength;
    char              tokenData[SKYGLOW_MAX_TOKEN_SIZE];
    char              error[256];
    uint8_t           padding[4];
} MachTokenResponseMessage;
#pragma pack()

int main(int argc, char *argv[]) {
    @autoreleasepool {
        const char *bundleID = (argc > 1) ? argv[1] : "com.apple.weather";
        printf("Requesting token for bundle ID: %s\n", bundleID);

        // Look up the daemon Mach service
        mach_port_t servicePort = MACH_PORT_NULL;
        kern_return_t kr = bootstrap_look_up(bootstrap_port,
                                              SKYGLOW_MACH_SERVICE_NAME_TOKEN,
                                              &servicePort);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "bootstrap_look_up failed: %s (%d)\n",
                    mach_error_string(kr), kr);
            return 1;
        }

        // Allocate a receive right for the reply.
        // Do NOT insert an additional send right — we pass the receive right
        // directly via MAKE_SEND_ONCE so the kernel creates a transient send-once
        // right for the daemon.  The daemon then uses MOVE_SEND_ONCE to reply,
        // consuming that right and delivering the message back to our receive port.
        mach_port_t replyPort = MACH_PORT_NULL;
        kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &replyPort);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "mach_port_allocate failed: %s (%d)\n",
                    mach_error_string(kr), kr);
            return 1;
        }

        // Build request
        MachTokenRequestMessage req;
        memset(&req, 0, sizeof(req));
        req.header.msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,
                                                       MACH_MSG_TYPE_MAKE_SEND_ONCE);
        req.header.msgh_size        = sizeof(req);
        req.header.msgh_remote_port = servicePort;
        req.header.msgh_local_port  = replyPort;   // receive right — kernel makes send-once
        req.header.msgh_id          = 1;
        req.body.msgh_descriptor_count = 0;
        req.type                    = SKYGLOW_REQUEST_TOKEN;
        strlcpy(req.bundleID, bundleID, sizeof(req.bundleID));

        kr = mach_msg(&req.header, MACH_SEND_MSG,
                       sizeof(req), 0, MACH_PORT_NULL,
                       MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "mach_msg send failed: %s (%d)\n",
                    mach_error_string(kr), kr);
            return 1;
        }
        printf("Request sent — waiting for response (up to 15s)...\n");

        // Receive reply on our receive port
        MachTokenResponseMessage resp;
        memset(&resp, 0, sizeof(resp));
        kr = mach_msg(&resp.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                       0, sizeof(resp), replyPort,
                       15000, MACH_PORT_NULL);

        if (kr == MACH_RCV_TIMED_OUT) {
            fprintf(stderr, "Timed out — daemon did not respond within 15s\n");
            fprintf(stderr, "Check daemon logs for errors\n");
            mach_port_deallocate(mach_task_self(), replyPort);
            return 1;
        }
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "mach_msg recv failed: %s (0x%x)\n",
                    mach_error_string(kr), kr);
            mach_port_deallocate(mach_task_self(), replyPort);
            return 1;
        }

        if (resp.type == SKYGLOW_ERROR || resp.tokenLength == 0) {
            fprintf(stderr, "Token generation failed: %s\n",
                    resp.error[0] ? resp.error : "(no error message)");
            mach_port_deallocate(mach_task_self(), replyPort);
            return 1;
        }

        printf("Token received (%u bytes):\n", resp.tokenLength);
        printf("  Hex: ");
        for (uint32_t i = 0; i < resp.tokenLength; i++) {
            printf("%02x", (unsigned char)resp.tokenData[i]);
        }
        printf("\n");

        // The routing key is SHA-256(K) where K is bytes 16-31 of the token.
        // Print it separately since that's what the server stores.
        // (On device you'd compute SHA-256 here; for now just print K in hex.)
        printf("  Key material (bytes 16-31): ");
        for (int i = 16; i < 32 && i < (int)resp.tokenLength; i++) {
            printf("%02x", (unsigned char)resp.tokenData[i]);
        }
        printf("\n");
        printf("\nVerify server row:\n");
        printf("  SELECT encode(routing_token,'hex'), bundle_id, issued_at\n");
        printf("  FROM notification_tokens WHERE bundle_id = '%s';\n", bundleID);

        mach_port_deallocate(mach_task_self(), replyPort);
        mach_port_deallocate(mach_task_self(), servicePort);
    }
    return 0;
}