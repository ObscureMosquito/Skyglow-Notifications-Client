#import "SNChannelGateway.h"
#import "../Skyglow-Notifications-Daemon/SGControlChannel.h"
#import "../Skyglow-Notifications-Daemon/SGControlChannelProtocol.h"
#include <string.h>

@implementation SNChannelGateway

static SGControlChannel *gDaemonClient = nil;
static SGControlChannel *gSpringBoardClient = nil;
static dispatch_once_t   gDaemonOnce;
static dispatch_once_t   gSpringBoardOnce;

static void SNCopyCString(char *dst, size_t dstSize, const char *src) {
    if (!dst || dstSize == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t i = 0;
    while (i + 1 < dstSize && src[i] != '\0') {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

static SGControlChannel *DaemonClient(void) {
    dispatch_once(&gDaemonOnce, ^{
        gDaemonClient = [SGControlChannel clientForServiceName:SKYGLOW_CONTROL_SERVICE_DAEMON];
        [gDaemonClient start];
    });
    return gDaemonClient;
}

static SGControlChannel *SpringBoardClient(void) {
    dispatch_once(&gSpringBoardOnce, ^{
        gSpringBoardClient = [SGControlChannel clientForServiceName:SKYGLOW_CONTROL_SERVICE_SPRINGBOARD];
        [gSpringBoardClient start];
    });
    return gSpringBoardClient;
}

+ (void)postReloadConfig {
    [DaemonClient() sendRequest:SGCMSG_RELOAD_CONFIG
                        payload:nil
                        timeout:0
                     completion:nil];
}

+ (void)postTestInject {
    [DaemonClient() sendRequest:SGCMSG_TEST_INJECT
                        payload:nil
                        timeout:0
                     completion:nil];
}

+ (void)postRegisterInputAppForBundleId:(NSString *)bundleId {
    if (bundleId.length == 0) return;
    SGCBundleIdPayload payload;
    memset(&payload, 0, sizeof(payload));
    SNCopyCString(payload.bundleID, sizeof(payload.bundleID), [bundleId UTF8String]);
    [SpringBoardClient() sendRequest:SGCMSG_REGISTER_INPUT_APP
                             payload:[NSData dataWithBytes:&payload length:sizeof(payload)]
                             timeout:0
                          completion:nil];
}

static void SendBundleCommandToDaemon(uint8_t messageType, NSString *bundleId) {
    if (bundleId.length == 0) return;
    SGCBundleIdPayload payload;
    memset(&payload, 0, sizeof(payload));
    SNCopyCString(payload.bundleID, sizeof(payload.bundleID), [bundleId UTF8String]);
    [DaemonClient() sendRequest:messageType
                        payload:[NSData dataWithBytes:&payload length:sizeof(payload)]
                        timeout:0
                     completion:nil];
}

+ (void)postEnableAppForBundleId:(NSString *)bundleId {
    SendBundleCommandToDaemon(SGCMSG_ENABLE_APP, bundleId);
}

+ (void)postDisableAppForBundleId:(NSString *)bundleId {
    SendBundleCommandToDaemon(SGCMSG_DISABLE_APP, bundleId);
}

+ (void)deleteAppForBundleId:(NSString *)bundleId completion:(SNChannelCommandCompletion)completion {
    if (bundleId.length == 0) {
        if (completion) completion(NO, @"The selected application could not be identified.");
        return;
    }

    SGCBundleIdPayload payload;
    memset(&payload, 0, sizeof(payload));
    SNCopyCString(payload.bundleID, sizeof(payload.bundleID), [bundleId UTF8String]);

    [DaemonClient() sendRequest:SGCMSG_DELETE_APP
                        payload:[NSData dataWithBytes:&payload length:sizeof(payload)]
                        timeout:SG_CONTROL_DELETE_APP_TIMEOUT_SEC
                     completion:^(SGControlError err, const SGControlChannelMessage *response) {
        BOOL ok = (err == SGCERR_OK);
        NSString *message = nil;
        if (!ok) {
            if (err == SGCERR_TIMEOUT || err == SGCERR_UNREACHABLE) {
                message = @"Could not communicate with SpringBoard. Try again after respringing.";
            } else {
                message = @"SpringBoard could not reset this application's notification registration.";
            }
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(ok, message);
        });
    }];
}

+ (void)subscribeToStatusUpdatesWithHandler:(void (^)(SGStatusPayload payload))handler {
    if (!handler) return;
    void (^handlerCopy)(SGStatusPayload) = [handler copy];

    SGControlChannel *client = DaemonClient();

    void (^doSubscribe)(void) = ^{
        [client subscribeToEvent:SGCEVT_STATE_CHANGED
                         handler:^(SGControlEventType eventType, NSData *data) {
            if ([data length] >= sizeof(SGStatusPayload)) {
                SGStatusPayload payload;
                memcpy(&payload, [data bytes], sizeof(payload));
                handlerCopy(payload);
            }
        } completion:nil];
    };

    /* Subscribe now (whether connected or not — channel will queue). */
    doSubscribe();

    /* Re-subscribe on every reconnect.  SGControlChannel clears event
     * handlers when the connection drops; without this, a daemon restart
     * leaves the subscription stranded. */
    [client setConnectionHandler:^(BOOL connected) {
        if (connected) doSubscribe();
    }];
}

+ (void)queryStatusWithCompletion:(void (^)(SGStatusPayload payload))completion {
    if (!completion) return;
    void (^completionCopy)(SGStatusPayload) = [completion copy];

    [DaemonClient() sendRequest:SGCMSG_QUERY_STATUS
                        payload:nil
                        timeout:0
                     completion:^(SGControlError err, const SGControlChannelMessage *response) {
        SGStatusPayload payload;
        memset(&payload, 0, sizeof(payload));
        if (err == SGCERR_OK && response &&
            response->payloadLength >= sizeof(SGStatusPayload)) {
            memcpy(&payload, response->payload, sizeof(payload));
        } else {
            payload.state = SGStateDisabled;
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            completionCopy(payload);
            [completionCopy release];
        });
    }];
}

+ (void)queryNativelyPushRegisteredBundlesWithCompletion:(SNChannelBundleListCompletion)completion {
    if (!completion) return;

    [SpringBoardClient() sendRequest:SGCMSG_LIST_PUSH_REGISTERED_APPS
                             payload:nil
                             timeout:0
                          completion:^(SGControlError err, const SGControlChannelMessage *response) {
        NSMutableArray *out = [NSMutableArray array];
        BOOL ok = (err == SGCERR_OK);
        NSString *message = nil;

        if (ok && response &&
            response->payloadLength >= offsetof(SGCBundleIdListPayload, data)) {
            SGCBundleIdListPayload *body = (SGCBundleIdListPayload *)response->payload;
            uint16_t count = body->count;
            const uint8_t *p   = body->data;
            const uint8_t *end = (const uint8_t *)response->payload + response->payloadLength;

            for (uint16_t i = 0; i < count; i++) {
                if ((NSInteger)(end - p) < 2) break;
                uint16_t len;
                memcpy(&len, p, sizeof(len));
                p += 2;
                if ((NSInteger)(end - p) < (NSInteger)len) break;
                NSString *bid = [[[NSString alloc] initWithBytes:p
                                                          length:len
                                                        encoding:NSUTF8StringEncoding] autorelease];
                if (bid.length) [out addObject:bid];
                p += len;
            }
        } else if (!ok) {
            if (err == SGCERR_TIMEOUT || err == SGCERR_UNREACHABLE) {
                message = @"Could not communicate with SpringBoard. Try again after respringing.";
            } else {
                message = @"SpringBoard could not return Apple Push registrations.";
            }
        } else {
            ok = NO;
            message = @"SpringBoard returned an invalid Apple Push registration list.";
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            completion(ok, out, message);
        });
    }];
}

@end
