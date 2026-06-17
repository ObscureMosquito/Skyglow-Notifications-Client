#import "SNChannelGateway.h"
#import "../Skyglow-Notifications-Daemon/SGControlChannel.h"
#import "../Skyglow-Notifications-Daemon/SGControlChannelProtocol.h"
#include <string.h>

@implementation SNChannelGateway

static SGControlChannel *gDaemonClient = nil;
static dispatch_once_t   gDaemonOnce;

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
    [DaemonClient() sendRequest:SGCMSG_REGISTER_INPUT_APP
                             payload:[NSData dataWithBytes:&payload length:sizeof(payload)]
                             timeout:0
                          completion:nil];
}

+ (void)registerInputAppForBundleId:(NSString *)bundleId
                         completion:(SNChannelCommandCompletion)completion {
    if (bundleId.length == 0) {
        if (completion) completion(NO, @"Bundle ID required.");
        return;
    }
    SGCBundleIdPayload payload;
    memset(&payload, 0, sizeof(payload));
    SNCopyCString(payload.bundleID, sizeof(payload.bundleID), [bundleId UTF8String]);
    [DaemonClient() sendRequest:SGCMSG_REGISTER_INPUT_APP
                             payload:[NSData dataWithBytes:&payload length:sizeof(payload)]
                             timeout:SG_CONTROL_DELETE_APP_TIMEOUT_SEC
                          completion:^(SGControlError err, const SGControlChannelMessage *response) {
        BOOL ok = (err == SGCERR_OK);
        NSString *message = nil;
        if (!ok) {
            message = (err == SGCERR_TIMEOUT || err == SGCERR_UNREACHABLE)
                ? @"Could not communicate with SpringBoard. Try again after respringing."
                : @"SpringBoard rejected the registration request.";
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(ok, message);
        });
    }];
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

+ (void)deleteProfileAtIndex:(NSInteger)profileIndex completion:(SNChannelCommandCompletion)completion {
    if (profileIndex < 1 || profileIndex > 5) {
        if (completion) completion(NO, @"Invalid profile index.");
        return;
    }

    SGCProfileIndexPayload payload;
    memset(&payload, 0, sizeof(payload));
    payload.profileIndex = (uint8_t)profileIndex;

    [DaemonClient() sendRequest:SGCMSG_DELETE_PROFILE
                        payload:[NSData dataWithBytes:&payload length:sizeof(payload)]
                        timeout:SG_CONTROL_DELETE_APP_TIMEOUT_SEC
                     completion:^(SGControlError err, const SGControlChannelMessage *response) {
        BOOL ok = (err == SGCERR_OK);
        NSString *message = nil;
        if (!ok) {
            if (err == SGCERR_TIMEOUT || err == SGCERR_UNREACHABLE) {
                message = @"Could not communicate with the Skyglow daemon. Try again after restarting it.";
            } else {
                message = @"The daemon could not delete this profile.";
            }
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(ok, message);
        });
    }];
}

+ (void)setActiveProfileAtIndex:(NSInteger)profileIndex completion:(SNChannelCommandCompletion)completion {
    if (profileIndex < 1 || profileIndex > 5) {
        if (completion) completion(NO, @"Invalid profile index.");
        return;
    }

    SGCProfileIndexPayload payload;
    memset(&payload, 0, sizeof(payload));
    payload.profileIndex = (uint8_t)profileIndex;

    [DaemonClient() sendRequest:SGCMSG_SET_ACTIVE_PROFILE
                        payload:[NSData dataWithBytes:&payload length:sizeof(payload)]
                        timeout:SG_CONTROL_DELETE_APP_TIMEOUT_SEC
                     completion:^(SGControlError err, const SGControlChannelMessage *response) {
        BOOL ok = (err == SGCERR_OK);
        NSString *message = nil;
        if (!ok) {
            if (err == SGCERR_TIMEOUT || err == SGCERR_UNREACHABLE) {
                message = @"Could not communicate with the Skyglow daemon. Try again after restarting it.";
            } else {
                message = @"The daemon could not switch to this profile.";
            }
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(ok, message);
        });
    }];
}

+ (void)saveProfileAtIndex:(NSInteger)profileIndex
             serverAddress:(NSString *)serverAddress
            certificatePEM:(NSString *)certificatePEM
                completion:(SNChannelCommandCompletion)completion {
    NSString *trimmed = [serverAddress stringByTrimmingCharactersInSet:
                         [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (profileIndex < 1 || profileIndex > 5) {
        if (completion) completion(NO, @"Invalid profile index.");
        return;
    }
    if (trimmed.length == 0) {
        if (completion) completion(NO, @"Enter a server address first.");
        return;
    }

    NSData *addressData = [trimmed dataUsingEncoding:NSUTF8StringEncoding];
    if ([addressData length] == 0 ||
        [addressData length] >= SG_CONTROL_MAX_SERVER_ADDRESS_SIZE) {
        if (completion) completion(NO, @"The server address is too long.");
        return;
    }

    NSData *pemData = [certificatePEM dataUsingEncoding:NSUTF8StringEncoding];
    if (pemData.length > SG_CONTROL_MAX_PROFILE_PEM_SIZE) {
        if (completion) completion(NO, @"The selected certificate is too large.");
        return;
    }

    SGCProfileSavePayload payload;
    memset(&payload, 0, sizeof(payload));
    payload.profileIndex = (uint8_t)profileIndex;
    payload.certificatePEMLength = (uint16_t)[pemData length];
    SNCopyCString(payload.serverAddress, sizeof(payload.serverAddress), [trimmed UTF8String]);
    if ([pemData length] > 0) {
        memcpy(payload.certificatePEM, [pemData bytes], [pemData length]);
    }

    [DaemonClient() sendRequest:SGCMSG_SAVE_PROFILE
                        payload:[NSData dataWithBytes:&payload length:sizeof(payload)]
                        timeout:0
                     completion:^(SGControlError err, const SGControlChannelMessage *response) {
        BOOL ok = (err == SGCERR_OK);
        NSString *message = nil;
        if (!ok) {
            if (err == SGCERR_TIMEOUT || err == SGCERR_UNREACHABLE) {
                message = @"Could not communicate with the Skyglow daemon. Try again after restarting it.";
            } else {
                message = @"The daemon could not save this profile.";
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

    doSubscribe();

    __block BOOL sawFirstConnect = NO;
    [client setConnectionHandler:^(BOOL connected) {
        if (!connected) return;
        doSubscribe();
        if (sawFirstConnect) {
            [self queryStatusWithCompletion:^(SGStatusPayload payload) {
                handlerCopy(payload);
            }];
        }
        sawFirstConnect = YES;
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

    [DaemonClient() sendRequest:SGCMSG_LIST_PUSH_REGISTERED_APPS
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
