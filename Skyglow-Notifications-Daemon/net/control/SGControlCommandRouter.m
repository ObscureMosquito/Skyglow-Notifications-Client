#import "SGControlCommandRouter.h"
#import "SGConfiguration.h"
#import "SGDaemon.h"
#import "SGStateStore.h"
#import "SGPlatform.h"
#import "SGControlChannel.h"
#import "SGControlChannelProtocol.h"
#import "SGControlPayloadCodec.h"
#import "SGDatabaseManager.h"
#import "SGStatus.h"
#import "SGProtocolHandler.h"
#import "SGTokenManager.h"
#import "SGLog.h"
#import "SGLogDiagnostics.h"
#include <signal.h>
#include <unistd.h>

typedef void (^SGCAckCompletion)(SGControlError error, NSString *detail);

static NSString *SGCDecodeBundleRequest(const SGControlChannelMessage *req,
                                        SGControlReplyErrorBlock replyError,
                                        NSString *what) {
    if (req->payloadLength < sizeof(SGCBundleIdPayload)) {
        replyError(SGCERR_INVALID_REQUEST,
                   [NSString stringWithFormat:@"%@ payload too short", what]);
        return nil;
    }
    NSString *bundleID = SGCBundleIdentifierDecode(req->payload, req->payloadLength);
    if (!bundleID) {
        replyError(SGCERR_INVALID_REQUEST,
                   [NSString stringWithFormat:@"%@ bundle id invalid", what]);
        return nil;
    }
    return bundleID;
}

static BOOL SGCRequirePlatform(id platform, SGControlReplyErrorBlock replyError) {
    if (platform) return YES;
    replyError(SGCERR_UNREACHABLE, @"platform unavailable");
    return NO;
}

static BOOL SGCRequireNativePlatform(id nativePlatform,
                                     SGControlReplyErrorBlock replyError) {
    if (nativePlatform) return YES;
    replyError(SGCERR_UNSUPPORTED,
               @"native push operations are unavailable on this platform");
    return NO;
}

static SGCAckCompletion SGCMakeAckCompletion(SGControlReplyBlock reply,
                                             SGControlReplyErrorBlock replyError,
                                             NSString *fallbackDetail) {
    SGControlReplyBlock      replyCopy      = [reply copy];
    SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
    SGCAckCompletion completion = ^(SGControlError error, NSString *detail) {
        if (error == SGCERR_OK) {
            replyCopy(SGCMSG_GENERIC_ACK, nil);
        } else {
            replyErrorCopy(error, [detail length] ? detail : fallbackDetail);
        }
        [replyCopy release];
        [replyErrorCopy release];
    };
    return [[completion copy] autorelease];
}

static void SGCDeferBoolReply(SGControlReplyBlock reply,
                              SGControlReplyErrorBlock replyError,
                              NSString *failureDetail,
                              BOOL (^work)(void)) {
    SGControlReplyBlock      replyCopy      = [reply copy];
    SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
    BOOL (^workCopy)(void) = [work copy];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            if (workCopy()) replyCopy(SGCMSG_GENERIC_ACK, nil);
            else            replyErrorCopy(SGCERR_INTERNAL, failureDetail);
        }
        [workCopy release];
        [replyCopy release];
        [replyErrorCopy release];
    });
}

@implementation SGControlCommandRouter {
    SGDaemon *_daemon;
}

- (instancetype)initWithDaemon:(SGDaemon *)daemon {
    if ((self = [super init])) {
        _daemon = [daemon retain];
    }
    return self;
}

- (void)dealloc {
    [_daemon release];
    [super dealloc];
}

- (void)attachToChannel:(SGControlChannel *)controlChannel {
    SGDaemon *daemon = _daemon;
    id<SGNotificationDelivery> platform = [SGPlatform currentPlatform].delivery;
    id<SGNativePushDelivery> nativePlatform =
        [(id)platform conformsToProtocol:@protocol(SGNativePushDelivery)]
            ? (id<SGNativePushDelivery>)platform : nil;

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        NSString *bundleID = SGCDecodeBundleRequest(req, replyError, @"token request");
        if (!bundleID) return;

        NSError *err = nil;
        SGTokenManager *tm = [[SGTokenManager alloc] init];
        NSData *token = [tm synchronizedTokenForBundleIdentifier:bundleID error:&err];

        if (!token) {
            NSString *detail = err ? [err localizedDescription] : @"Token generation failed";
            replyError(SGCERR_INTERNAL, detail);
            [tm release];
            return;
        }

        if ([token length] > SG_CONTROL_MAX_TOKEN_SIZE) {
            replyError(SGCERR_INTERNAL, @"token exceeds wire limit");
            [tm release];
            return;
        }

        SGCTokenResponsePayload resp;
        memset(&resp, 0, sizeof(resp));
        resp.tokenLength = (uint32_t)[token length];
        memcpy(resp.tokenData, [token bytes], [token length]);
        reply(SGCMSG_TOKEN_RESPONSE, [NSData dataWithBytes:&resp length:sizeof(resp)]);

        if (tm) {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                SGP_FlushActiveTopicFilter();
            });
            [tm release];
        }
    } forMessageType:SGCMSG_TOKEN_REQUEST];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            @autoreleasepool { [daemon handleConfigurationReloadRequest]; }
        });
        reply(SGCMSG_GENERIC_ACK, nil);
    } forMessageType:SGCMSG_RELOAD_CONFIG];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        (void)req;
        (void)replyError;
        reply(SGCMSG_GENERIC_ACK, nil);

        // Let the ack leave before bounded shutdown; launchd owns the restart.
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                     (int64_t)(250 * NSEC_PER_MSEC)),
                       dispatch_get_main_queue(), ^{
            kill(getpid(), SIGTERM);
        });
    } forMessageType:SGCMSG_RESTART_DAEMON];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        SGStatusPayload snapshot;
        SGStatus_Current(&snapshot);
        reply(SGCMSG_STATUS_RESPONSE,
              [NSData dataWithBytes:&snapshot length:sizeof(snapshot)]);
    } forMessageType:SGCMSG_QUERY_STATUS];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        if (req->payloadLength < sizeof(SGCProfileSavePayload)) {
            replyError(SGCERR_INVALID_REQUEST, @"save-profile payload too short");
            return;
        }
        SGCProfileSavePayload *p = (SGCProfileSavePayload *)req->payload;
        NSInteger idx = p->profileIndex;
        if (!SGProfileIndexIsValid(idx) ||
            p->certificatePEMLength > SG_CONTROL_MAX_PROFILE_PEM_SIZE) {
            replyError(SGCERR_INVALID_REQUEST, @"save-profile payload invalid");
            return;
        }

        NSString *address = [[NSString alloc] initWithBytes:p->serverAddress
                                                     length:strnlen(p->serverAddress, sizeof(p->serverAddress))
                                                   encoding:NSUTF8StringEncoding];
        NSString *pem = nil;
        if (p->certificatePEMLength > 0) {
            pem = [[NSString alloc] initWithBytes:p->certificatePEM
                                           length:p->certificatePEMLength
                                         encoding:NSUTF8StringEncoding];
        }
        if ([address length] == 0 || (p->certificatePEMLength > 0 && [pem length] == 0)) {
            [address release];
            [pem release];
            replyError(SGCERR_INVALID_REQUEST, @"save-profile payload strings invalid");
            return;
        }
        if ([pem length] > 0 && !SG_LooksLikePEMCertificate(pem)) {
            [address release];
            [pem release];
            replyError(SGCERR_INVALID_REQUEST,
                       @"file does not look like a PEM-encoded server certificate");
            return;
        }

        SGCDeferBoolReply(reply, replyError, @"profile save failed", ^BOOL{
            return [daemon performSaveProfileAtIndex:idx
                                       serverAddress:address
                                      certificatePEM:pem];
        });
        [address release];
        [pem release];
    } forMessageType:SGCMSG_SAVE_PROFILE];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        if (req->payloadLength < sizeof(SGCRegIdentityPayload)) {
            replyError(SGCERR_INVALID_REQUEST, @"reg-identity payload too short");
            return;
        }
        SGCRegIdentityPayload *p = (SGCRegIdentityPayload *)req->payload;
        NSInteger idx = p->profileIndex;
        if (!SGProfileIndexIsValid(idx) ||
            p->identityPEMLength > SG_CONTROL_MAX_REG_IDENTITY_PEM_SIZE) {
            replyError(SGCERR_INVALID_REQUEST, @"reg-identity payload invalid");
            return;
        }

        NSString *pem = nil;
        if (p->identityPEMLength > 0) {
            pem = [[NSString alloc] initWithBytes:p->identityPEM
                                           length:p->identityPEMLength
                                         encoding:NSUTF8StringEncoding];
            if ([pem length] == 0) {
                [pem release];
                replyError(SGCERR_INVALID_REQUEST, @"reg-identity payload strings invalid");
                return;
            }
        }

        SGCDeferBoolReply(reply, replyError, @"reg-identity update failed", ^BOOL{
            return [daemon performSetRegistrationIdentityAtIndex:idx
                                                     identityPEM:pem];
        });
        [pem release];
    } forMessageType:SGCMSG_SET_REG_IDENTITY];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        if (req->payloadLength < sizeof(SGCProfileIndexPayload)) {
            replyError(SGCERR_INVALID_REQUEST, @"delete-profile payload too short");
            return;
        }
        SGCProfileIndexPayload *p = (SGCProfileIndexPayload *)req->payload;
        NSInteger idx = p->profileIndex;
        if (!SGProfileIndexIsValid(idx)) {
            replyError(SGCERR_INVALID_REQUEST, @"profile index out of range");
            return;
        }

        SGCDeferBoolReply(reply, replyError, @"profile delete failed", ^BOOL{
            return [daemon performDeleteProfileAtIndex:idx];
        });
    } forMessageType:SGCMSG_DELETE_PROFILE];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        if (req->payloadLength < sizeof(SGCProfileIndexPayload)) {
            replyError(SGCERR_INVALID_REQUEST, @"set-active payload too short");
            return;
        }
        SGCProfileIndexPayload *p = (SGCProfileIndexPayload *)req->payload;
        NSInteger idx = p->profileIndex;
        if (!SGProfileIndexIsValid(idx)) {
            replyError(SGCERR_INVALID_REQUEST, @"profile index out of range");
            return;
        }

        SGCDeferBoolReply(reply, replyError, @"set-active failed", ^BOOL{
            return [daemon performSetActiveProfileAtIndex:idx];
        });
    } forMessageType:SGCMSG_SET_ACTIVE_PROFILE];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        if (req->payloadLength < sizeof(SGCEnabledPayload)) {
            replyError(SGCERR_INVALID_REQUEST, @"set-enabled payload too short");
            return;
        }
        SGCEnabledPayload *ep = (SGCEnabledPayload *)req->payload;
        if (ep->enabled > 1) {
            replyError(SGCERR_INVALID_REQUEST, @"set-enabled value invalid");
            return;
        }
        BOOL enabled = (ep->enabled != 0);

        BOOL ok = [daemon performSetEnabled:enabled];
        if (ok) reply(SGCMSG_GENERIC_ACK, nil);
        else    replyError(SGCERR_INTERNAL, @"could not persist enabled state");
    } forMessageType:SGCMSG_SET_ENABLED];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        NSString *bundleID = SGCDecodeBundleRequest(req, replyError, @"test notification");
        if (!bundleID) return;
        if (!SGCRequirePlatform(platform, replyError)) return;

        NSString *bundleCopy = [bundleID copy];
        SGControlReplyBlock replyCopy = [reply copy];
        SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
        dispatch_async(dispatch_get_global_queue(
            DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            @autoreleasepool {
                NSDictionary *testPayload = @{
                    @"title": @"Skyglow Notifications",
                    @"body": [NSString stringWithFormat:
                        @"Native delivery test for %@", bundleCopy],
                    @"sound": @"default"
                };
                kern_return_t result = [platform
                    sendNotificationForBundleID:bundleCopy
                                         payload:testPayload];
                SGLOGI(Skyglow,
                    "code=%s message=TEST_INJECT bundle=%s result=%s",
                    SGND_DAEMON_TEST_INJECT, [bundleCopy UTF8String],
                    result == KERN_SUCCESS ? "delivered" : "rejected");
                if (result == KERN_SUCCESS) {
                    replyCopy(SGCMSG_GENERIC_ACK, nil);
                } else {
                    replyErrorCopy(SGCERR_INTERNAL,
                        @"native notification delivery was rejected");
                }
            }
            [bundleCopy release];
            [replyCopy release];
            [replyErrorCopy release];
        });
    } forMessageType:SGCMSG_TEST_INJECT];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        NSString *bundleID = SGCDecodeBundleRequest(req, replyError, @"enable");
        if (!bundleID) return;
        BOOL ok = [daemon.stateStore performSetAppEnabled:YES
                           forBundleIdentifier:bundleID];
        if (ok) reply(SGCMSG_GENERIC_ACK, nil);
        else    replyError(SGCERR_INTERNAL, @"could not persist enabled application state");
    } forMessageType:SGCMSG_ENABLE_APP];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        NSString *bundleID = SGCDecodeBundleRequest(req, replyError, @"disable");
        if (!bundleID) return;
        BOOL ok = [daemon.stateStore performSetAppEnabled:NO
                           forBundleIdentifier:bundleID];
        if (ok) reply(SGCMSG_GENERIC_ACK, nil);
        else    replyError(SGCERR_INTERNAL, @"could not persist disabled application state");
    } forMessageType:SGCMSG_DISABLE_APP];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        NSString *bundleID = SGCDecodeBundleRequest(req, replyError, @"clear-app-intent");
        if (!bundleID) return;
        BOOL ok = [daemon.stateStore performClearAppIntentForBundleIdentifier:bundleID];
        if (ok) reply(SGCMSG_GENERIC_ACK, nil);
        else    replyError(SGCERR_INTERNAL, @"could not clear application intent");
    } forMessageType:SGCMSG_CLEAR_APP_INTENT];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        NSString *bundleID = SGCDecodeBundleRequest(req, replyError, @"delete");
        if (!bundleID) return;
        if (!SGCRequirePlatform(platform, replyError)) return;

        NSString *bundleRet = [bundleID retain];
        SGControlReplyBlock replyCopy = [reply copy];
        SGControlReplyErrorBlock replyErrorCopy = [replyError copy];

        [platform resetAppRegistrationForBundleID:bundleRet
                                       completion:^(SGControlError err,
                                                    NSString *resetDetail) {
            if (err == SGCERR_OK) {
                if ([daemon.stateStore performDeleteAppStateForBundleIdentifier:bundleRet]) {
                    replyCopy(SGCMSG_GENERIC_ACK, nil);
                } else {
                    replyErrorCopy(SGCERR_INTERNAL,
                                   @"could not persist application deletion");
                }
            } else {
                NSString *detail = [resetDetail length] ? resetDetail
                    : ((err == SGCERR_TIMEOUT || err == SGCERR_UNREACHABLE)
                        ? @"delivery platform did not respond"
                        : @"registration reset was rejected");
                replyErrorCopy(err, detail);
            }

            [bundleRet release];
            [replyCopy release];
            [replyErrorCopy release];
        }];
    } forMessageType:SGCMSG_DELETE_APP];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        NSString *bundleID = SGCDecodeBundleRequest(req, replyError, @"native reset");
        if (!bundleID) return;
        if (!SGCRequirePlatform(platform, replyError)) return;

        [platform resetAppRegistrationForBundleID:bundleID
                                       completion:SGCMakeAckCompletion(
                                           reply, replyError, @"native reset failed")];
    } forMessageType:SGCMSG_RESET_APP_REGISTRATION];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        if (!SGCRequireNativePlatform(nativePlatform, replyError)) return;
        SGControlReplyBlock      replyCopy      = [reply copy];
        SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
        [nativePlatform listNativePushAppsWithCompletion:^(SGControlError err, NSData *listPayload) {
            if (err == SGCERR_OK) replyCopy(SGCMSG_BUNDLE_ID_LIST, listPayload);
            else replyErrorCopy(err, (err == SGCERR_TIMEOUT || err == SGCERR_UNREACHABLE)
                    ? @"presenter did not respond" : @"list request rejected");
            [replyCopy release];
            [replyErrorCopy release];
        }];
    } forMessageType:SGCMSG_LIST_NATIVE_PUSH_APPS];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        NSString *bundleID = SGCDecodeBundleRequest(req, replyError, @"native registration");
        if (!bundleID) return;
        if (!SGCRequireNativePlatform(nativePlatform, replyError)) return;

        [nativePlatform registerNativePushAppForBundleID:bundleID
                                              completion:SGCMakeAckCompletion(
                                                  reply, replyError,
                                                  @"native registration failed")];
    } forMessageType:SGCMSG_REGISTER_NATIVE_PUSH_APP];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        NSString *bundleID = SGCDecodeBundleRequest(req, replyError, @"native authorization");
        if (!bundleID) return;
        if (!SGCRequireNativePlatform(nativePlatform, replyError)) return;

        [nativePlatform
            requestNativeNotificationAuthorizationForBundleID:bundleID
            completion:SGCMakeAckCompletion(reply, replyError,
                                            @"native authorization request failed")];
    } forMessageType:SGCMSG_AUTHORIZE_NATIVE_PUSH_APP];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        reply(SGCMSG_BUNDLE_ID_LIST,
              SGCBundleIdListEncode([[SGDatabaseManager sharedManager] registeredBundleIdentifiers]));
    } forMessageType:SGCMSG_LIST_SKYGLOW_APPS];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        NSString *bundleID = SGCDecodeBundleRequest(req, replyError, @"register-input");
        if (!bundleID) return;
        if (!SGCRequireNativePlatform(nativePlatform, replyError)) return;
        NSString *bundleCopy = [bundleID copy];
        SGControlReplyBlock      replyCopy      = [reply copy];
        SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
        [nativePlatform registerInputAppForBundleID:bundleCopy completion:^(SGControlError err, NSString *detail) {
            if (err == SGCERR_OK) {
                // Commit ownership before acking so the app list stays consistent.
                BOOL committed = [daemon.stateStore
                    performSetAppEnabled:YES
                    forBundleIdentifier:bundleCopy];
                if (committed) {
                    replyCopy(SGCMSG_GENERIC_ACK, nil);
                } else {
                    replyErrorCopy(SGCERR_INTERNAL,
                        @"Skyglow token exists but application intent could not be persisted");
                }
            } else {
                replyErrorCopy(err,
                    [detail length] ? detail : @"register request failed");
            }
            [bundleCopy release];
            [replyCopy release];
            [replyErrorCopy release];
        }];
    } forMessageType:SGCMSG_REGISTER_INPUT_APP];
}

@end
