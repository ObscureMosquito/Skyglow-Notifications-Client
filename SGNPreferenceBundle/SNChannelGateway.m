#import "SNChannelGateway.h"
#import "SGControlChannel.h"
#import "SGControlChannelProtocol.h"
#import "SGControlPayloadCodec.h"
#import "SGConfiguration.h"
#include <string.h>

@implementation SNChannelGateway

static SGControlChannel *gDaemonClient = nil;
static dispatch_once_t   gDaemonOnce;

static NSString * const kSNDaemonUnreachableMessage =
    @"Could not communicate with the Skyglow daemon. Try again after restarting it.";
static NSString * const kSNSpringBoardUnreachableMessage =
    @"Could not communicate with SpringBoard. Try again after respringing.";

static SGControlChannel *DaemonClient(void) {
    dispatch_once(&gDaemonOnce, ^{
        gDaemonClient = [SGControlChannel clientForServiceName:SKYGLOW_CONTROL_SERVICE_DAEMON];
        [gDaemonClient start];
    });
    return gDaemonClient;
}

static NSData *SNBundleIdPayloadData(NSString *bundleId) {
    SGCBundleIdPayload payload;
    memset(&payload, 0, sizeof(payload));
    SGCCopyCString(payload.bundleID, sizeof(payload.bundleID), [bundleId UTF8String]);
    return [NSData dataWithBytes:&payload length:sizeof(payload)];
}

static NSData *SNProfileIndexPayloadData(NSInteger profileIndex) {
    SGCProfileIndexPayload payload;
    memset(&payload, 0, sizeof(payload));
    payload.profileIndex = (uint8_t)profileIndex;
    return [NSData dataWithBytes:&payload length:sizeof(payload)];
}

static void SNSendCommand(uint8_t messageType, NSData *payloadData, uint32_t timeout,
                          NSString *unreachableMessage, NSString *rejectedMessage,
                          SNChannelCommandCompletion completion) {
    [DaemonClient() sendRequest:messageType
                        payload:payloadData
                        timeout:timeout
                     completion:^(SGControlError err, const SGControlChannelMessage *response) {
        BOOL ok = (err == SGCERR_OK);
        NSString *message = nil;
        if (!ok) {
            message = SGCErrorDetailFromResponse(response);
            if (message.length == 0) {
                message = (err == SGCERR_TIMEOUT || err == SGCERR_UNREACHABLE)
                    ? unreachableMessage : rejectedMessage;
            }
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(ok, message);
        });
    }];
}

+ (void)postReloadConfig {
    [DaemonClient() sendRequest:SGCMSG_RELOAD_CONFIG
                        payload:nil
                        timeout:0
                     completion:nil];
}

+ (void)restartDaemonWithCompletion:(SNChannelCommandCompletion)completion {
    SNSendCommand(SGCMSG_RESTART_DAEMON, nil, SG_CONTROL_DEFAULT_REQUEST_TIMEOUT_SEC,
                  @"The daemon could not be reached.",
                  @"The daemon rejected the restart request.", completion);
}

+ (void)postTestInject {
    [DaemonClient() sendRequest:SGCMSG_TEST_INJECT
                        payload:nil
                        timeout:0
                     completion:nil];
}

+ (void)postRegisterInputAppForBundleId:(NSString *)bundleId {
    if (bundleId.length == 0) return;
    [DaemonClient() sendRequest:SGCMSG_REGISTER_INPUT_APP
                        payload:SNBundleIdPayloadData(bundleId)
                        timeout:0
                     completion:nil];
}

+ (void)registerInputAppForBundleId:(NSString *)bundleId
                         completion:(SNChannelCommandCompletion)completion {
    if (bundleId.length == 0) {
        if (completion) completion(NO, @"Bundle ID required.");
        return;
    }
    SNSendCommand(SGCMSG_REGISTER_INPUT_APP, SNBundleIdPayloadData(bundleId),
                  SG_CONTROL_DELETE_APP_TIMEOUT_SEC,
                  kSNSpringBoardUnreachableMessage,
                  @"SpringBoard rejected the registration request.", completion);
}

static void SendBundleCommandWithCompletion(uint8_t messageType, NSString *bundleId,
                                            SNChannelCommandCompletion completion) {
    if (bundleId.length == 0) {
        if (completion) completion(NO, @"The selected application could not be identified.");
        return;
    }
    SNSendCommand(messageType, SNBundleIdPayloadData(bundleId),
                  SG_CONTROL_DELETE_APP_TIMEOUT_SEC,
                  kSNDaemonUnreachableMessage,
                  @"The daemon could not update this application.", completion);
}

+ (void)enableAppForBundleId:(NSString *)bundleId completion:(SNChannelCommandCompletion)completion {
    SendBundleCommandWithCompletion(SGCMSG_ENABLE_APP, bundleId, completion);
}

+ (void)disableAppForBundleId:(NSString *)bundleId completion:(SNChannelCommandCompletion)completion {
    SendBundleCommandWithCompletion(SGCMSG_DISABLE_APP, bundleId, completion);
}

+ (void)setEnabled:(BOOL)enabled completion:(SNChannelCommandCompletion)completion {
    SGCEnabledPayload payload;
    memset(&payload, 0, sizeof(payload));
    payload.enabled = enabled ? 1 : 0;
    SNSendCommand(SGCMSG_SET_ENABLED,
                  [NSData dataWithBytes:&payload length:sizeof(payload)],
                  SG_CONTROL_DELETE_APP_TIMEOUT_SEC,
                  kSNDaemonUnreachableMessage,
                  @"The daemon could not change the enabled state.", completion);
}

+ (void)deleteAppForBundleId:(NSString *)bundleId completion:(SNChannelCommandCompletion)completion {
    if (bundleId.length == 0) {
        if (completion) completion(NO, @"The selected application could not be identified.");
        return;
    }
    SNSendCommand(SGCMSG_DELETE_APP, SNBundleIdPayloadData(bundleId),
                  SG_CONTROL_DELETE_APP_TIMEOUT_SEC,
                  kSNSpringBoardUnreachableMessage,
                  @"SpringBoard could not reset this application's notification registration.",
                  completion);
}

+ (void)deleteProfileAtIndex:(NSInteger)profileIndex completion:(SNChannelCommandCompletion)completion {
    if (!SGProfileIndexIsValid(profileIndex)) {
        if (completion) completion(NO, @"Invalid profile index.");
        return;
    }
    SNSendCommand(SGCMSG_DELETE_PROFILE, SNProfileIndexPayloadData(profileIndex),
                  SG_CONTROL_DELETE_APP_TIMEOUT_SEC,
                  kSNDaemonUnreachableMessage,
                  @"The daemon could not delete this profile.", completion);
}

+ (void)setActiveProfileAtIndex:(NSInteger)profileIndex completion:(SNChannelCommandCompletion)completion {
    if (!SGProfileIndexIsValid(profileIndex)) {
        if (completion) completion(NO, @"Invalid profile index.");
        return;
    }
    SNSendCommand(SGCMSG_SET_ACTIVE_PROFILE, SNProfileIndexPayloadData(profileIndex),
                  SG_CONTROL_DELETE_APP_TIMEOUT_SEC,
                  kSNDaemonUnreachableMessage,
                  @"The daemon could not switch to this profile.", completion);
}

+ (void)saveProfileAtIndex:(NSInteger)profileIndex
             serverAddress:(NSString *)serverAddress
            certificatePEM:(NSString *)certificatePEM
                completion:(SNChannelCommandCompletion)completion {
    NSString *trimmed = [serverAddress stringByTrimmingCharactersInSet:
                         [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (!SGProfileIndexIsValid(profileIndex)) {
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
    SGCCopyCString(payload.serverAddress, sizeof(payload.serverAddress), [trimmed UTF8String]);
    if ([pemData length] > 0) {
        memcpy(payload.certificatePEM, [pemData bytes], [pemData length]);
    }

    SNSendCommand(SGCMSG_SAVE_PROFILE,
                  [NSData dataWithBytes:&payload length:sizeof(payload)],
                  0, kSNDaemonUnreachableMessage,
                  @"The daemon could not save this profile.", completion);
}

+ (void)setRegistrationIdentityAtIndex:(NSInteger)profileIndex
                           identityPEM:(NSString *)identityPEM
                            completion:(SNChannelCommandCompletion)completion {
    if (!SGProfileIndexIsValid(profileIndex)) {
        if (completion) completion(NO, @"Invalid profile index.");
        return;
    }

    NSData *pemData = [identityPEM dataUsingEncoding:NSUTF8StringEncoding];
    if (pemData.length > SG_CONTROL_MAX_REG_IDENTITY_PEM_SIZE) {
        if (completion) completion(NO, @"The selected identity file is too large.");
        return;
    }

    SGCRegIdentityPayload payload;
    memset(&payload, 0, sizeof(payload));
    payload.profileIndex = (uint8_t)profileIndex;
    payload.identityPEMLength = (uint16_t)[pemData length];
    if ([pemData length] > 0) {
        memcpy(payload.identityPEM, [pemData bytes], [pemData length]);
    }

    SNSendCommand(SGCMSG_SET_REG_IDENTITY,
                  [NSData dataWithBytes:&payload length:sizeof(payload)],
                  0, kSNDaemonUnreachableMessage,
                  @"The daemon rejected the registration identity. It must be a PEM file containing the certificate and its private key.",
                  completion);
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

    [DaemonClient() sendRequest:SGCMSG_LIST_NATIVE_PUSH_APPS
                             payload:nil
                             timeout:0
                          completion:^(SGControlError err, const SGControlChannelMessage *response) {
        NSMutableArray *out = [NSMutableArray array];
        BOOL ok = (err == SGCERR_OK);
        NSString *message = nil;

        if (ok && response &&
            response->payloadLength >= offsetof(SGCBundleIdListPayload, data)) {
            [out addObjectsFromArray:SGCBundleIdListDecode(response->payload, response->payloadLength)];
        } else if (!ok) {
            message = SGCErrorDetailFromResponse(response);
            if (message.length == 0) {
                message = (err == SGCERR_TIMEOUT || err == SGCERR_UNREACHABLE)
                    ? kSNSpringBoardUnreachableMessage
                    : @"SpringBoard could not return Apple Push registrations.";
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
