#import "SGControlCommandRouter.h"
#import "SGDaemon.h"
#import "SGStateStore.h"
#import "SGPlatform.h"
#import "SGControlChannel.h"
#import "SGControlChannelProtocol.h"
#import "SGControlPayloadCodec.h"
#import "SGDatabaseManager.h"
#import "SGStatusServer.h"
#import "SGProtocolHandler.h"
#import "SGTokenManager.h"
#import "SGLog.h"
#import "SGLogDiagnostics.h"

@implementation SGControlCommandRouter {
    SGDaemon   *_daemon;
    SGPlatform *_platform;
}

- (instancetype)initWithDaemon:(SGDaemon *)daemon platform:(SGPlatform *)platform {
    if ((self = [super init])) {
        _daemon = [daemon retain];
        _platform = [platform retain];
    }
    return self;
}

- (void)dealloc {
    [_daemon release];
    [_platform release];
    [super dealloc];
}

- (void)attachToChannel:(SGControlChannel *)controlChannel {
    SGDaemon   *daemon   = _daemon;
    SGPlatform *platform = _platform;

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        if (req->payloadLength < sizeof(SGCTokenRequestPayload)) {
            replyError(SGCERR_INVALID_REQUEST, @"token request payload too short");
            return;
        }
        SGCTokenRequestPayload *tReq = (SGCTokenRequestPayload *)req->payload;
        NSString *bundleID = [[NSString alloc] initWithBytes:tReq->bundleID
                                                      length:strnlen(tReq->bundleID, sizeof(tReq->bundleID))
                                                    encoding:NSUTF8StringEncoding];
        if (!SG_IsIdentifierStringSafe(bundleID)) {
            [bundleID release];
            replyError(SGCERR_INVALID_REQUEST, @"token request bundle id invalid");
            return;
        }

        NSError *err = nil;
        SGTokenManager *tm = [[SGTokenManager alloc] init];
        NSData *token = [tm synchronizedTokenForBundleIdentifier:bundleID error:&err];

        if (!token) {
            NSString *detail = err ? [err localizedDescription] : @"Token generation failed";
            replyError(SGCERR_INTERNAL, detail);
            [tm release];
            [bundleID release];
            return;
        }

        if ([token length] > SG_CONTROL_MAX_TOKEN_SIZE) {
            replyError(SGCERR_INTERNAL, @"token exceeds wire limit");
            [tm release];
            [bundleID release];
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
        [bundleID release];
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
        SGStatusPayload snapshot;
        SGStatusServer_Current(&snapshot);
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
        if (idx < 1 || idx > 5 ||
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

        SGControlReplyBlock      replyCopy      = [reply copy];
        SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
        NSString *addressCopy = [address copy];
        NSString *pemCopy = [pem copy];
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            @autoreleasepool {
                BOOL ok = [daemon performSaveProfileAtIndex:idx
                                               serverAddress:addressCopy
                                               certificatePEM:pemCopy];
                if (ok) replyCopy(SGCMSG_GENERIC_ACK, nil);
                else    replyErrorCopy(SGCERR_INTERNAL, @"profile save failed");
            }
            [addressCopy release];
            [pemCopy release];
            [replyCopy release];
            [replyErrorCopy release];
        });
        [address release];
        [pem release];
    } forMessageType:SGCMSG_SAVE_PROFILE];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        if (req->payloadLength < sizeof(SGCProfileIndexPayload)) {
            replyError(SGCERR_INVALID_REQUEST, @"delete-profile payload too short");
            return;
        }
        SGCProfileIndexPayload *p = (SGCProfileIndexPayload *)req->payload;
        NSInteger idx = p->profileIndex;
        if (idx < 1 || idx > 5) {
            replyError(SGCERR_INVALID_REQUEST, @"profile index out of range");
            return;
        }

        SGControlReplyBlock      replyCopy      = [reply copy];
        SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            @autoreleasepool {
                BOOL ok = [daemon performDeleteProfileAtIndex:idx];
                if (ok) replyCopy(SGCMSG_GENERIC_ACK, nil);
                else    replyErrorCopy(SGCERR_INTERNAL, @"profile delete failed");
            }
            [replyCopy release];
            [replyErrorCopy release];
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
        if (idx < 1 || idx > 5) {
            replyError(SGCERR_INVALID_REQUEST, @"profile index out of range");
            return;
        }

        SGControlReplyBlock      replyCopy      = [reply copy];
        SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            @autoreleasepool {
                BOOL ok = [daemon performSetActiveProfileAtIndex:idx];
                if (ok) replyCopy(SGCMSG_GENERIC_ACK, nil);
                else    replyErrorCopy(SGCERR_INTERNAL, @"set-active failed");
            }
            [replyCopy release];
            [replyErrorCopy release];
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
        SGLOGI(Skyglow, "code=%s message=TEST_INJECT result=received", SGND_DAEMON_TEST_INJECT);
        reply(SGCMSG_GENERIC_ACK, nil);
    } forMessageType:SGCMSG_TEST_INJECT];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        if (req->payloadLength < sizeof(SGCBundleIdPayload)) {
            replyError(SGCERR_INVALID_REQUEST, @"enable payload too short");
            return;
        }
        SGCBundleIdPayload *bp = (SGCBundleIdPayload *)req->payload;
        NSString *bundleID = [[NSString alloc] initWithBytes:bp->bundleID
                                                      length:strnlen(bp->bundleID, sizeof(bp->bundleID))
                                                    encoding:NSUTF8StringEncoding];
        if (!SG_IsIdentifierStringSafe(bundleID)) {
            [bundleID release];
            replyError(SGCERR_INVALID_REQUEST, @"enable bundle id invalid");
            return;
        }
        BOOL ok = [daemon.stateStore performSetAppEnabled:YES
                           forBundleIdentifier:bundleID];
        [bundleID release];
        if (ok) reply(SGCMSG_GENERIC_ACK, nil);
        else    replyError(SGCERR_INTERNAL, @"could not persist enabled application state");
    } forMessageType:SGCMSG_ENABLE_APP];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        if (req->payloadLength < sizeof(SGCBundleIdPayload)) {
            replyError(SGCERR_INVALID_REQUEST, @"disable payload too short");
            return;
        }
        SGCBundleIdPayload *bp = (SGCBundleIdPayload *)req->payload;
        NSString *bundleID = [[NSString alloc] initWithBytes:bp->bundleID
                                                      length:strnlen(bp->bundleID, sizeof(bp->bundleID))
                                                    encoding:NSUTF8StringEncoding];
        if (!SG_IsIdentifierStringSafe(bundleID)) {
            [bundleID release];
            replyError(SGCERR_INVALID_REQUEST, @"disable bundle id invalid");
            return;
        }
        BOOL ok = [daemon.stateStore performSetAppEnabled:NO
                           forBundleIdentifier:bundleID];
        [bundleID release];
        if (ok) reply(SGCMSG_GENERIC_ACK, nil);
        else    replyError(SGCERR_INTERNAL, @"could not persist disabled application state");
    } forMessageType:SGCMSG_DISABLE_APP];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        if (req->payloadLength < sizeof(SGCBundleIdPayload)) {
            replyError(SGCERR_INVALID_REQUEST, @"clear-app-intent payload too short");
            return;
        }
        SGCBundleIdPayload *bp = (SGCBundleIdPayload *)req->payload;
        NSString *bundleID = [[NSString alloc] initWithBytes:bp->bundleID
                                                      length:strnlen(bp->bundleID, sizeof(bp->bundleID))
                                                    encoding:NSUTF8StringEncoding];
        if (!SG_IsIdentifierStringSafe(bundleID)) {
            [bundleID release];
            replyError(SGCERR_INVALID_REQUEST, @"clear-app-intent bundle id invalid");
            return;
        }
        BOOL ok = [daemon.stateStore performClearAppIntentForBundleIdentifier:bundleID];
        [bundleID release];
        if (ok) reply(SGCMSG_GENERIC_ACK, nil);
        else    replyError(SGCERR_INTERNAL, @"could not clear application intent");
    } forMessageType:SGCMSG_CLEAR_APP_INTENT];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        if (req->payloadLength < sizeof(SGCBundleIdPayload)) {
            replyError(SGCERR_INVALID_REQUEST, @"delete payload too short");
            return;
        }
        SGCBundleIdPayload *bp = (SGCBundleIdPayload *)req->payload;
        NSString *bundleID = [[NSString alloc] initWithBytes:bp->bundleID
                                                      length:strnlen(bp->bundleID, sizeof(bp->bundleID))
                                                    encoding:NSUTF8StringEncoding];
        if (!SG_IsIdentifierStringSafe(bundleID)) {
            [bundleID release];
            replyError(SGCERR_INVALID_REQUEST, @"delete bundle id invalid");
            return;
        }
        if (!platform) {
            [bundleID release];
            replyError(SGCERR_UNREACHABLE, @"platform unavailable");
            return;
        }

        NSString *bundleRet = [bundleID retain];
        SGControlReplyBlock replyCopy = [reply copy];
        SGControlReplyErrorBlock replyErrorCopy = [replyError copy];

        [platform resetAppRegistrationForBundleID:bundleRet
                                       completion:^(SGControlError err) {
            if (err == SGCERR_OK) {
                if ([daemon.stateStore performDeleteAppStateForBundleIdentifier:bundleRet]) {
                    replyCopy(SGCMSG_GENERIC_ACK, nil);
                } else {
                    replyErrorCopy(SGCERR_INTERNAL,
                                   @"could not persist application deletion");
                }
            } else {
                NSString *detail = (err == SGCERR_TIMEOUT || err == SGCERR_UNREACHABLE)
                    ? @"SpringBoard did not respond"
                    : @"SpringBoard rejected the reset request";
                replyErrorCopy(err, detail);
            }

            [bundleRet release];
            [replyCopy release];
            [replyErrorCopy release];
        }];
        [bundleID release];
    } forMessageType:SGCMSG_DELETE_APP];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        if (!platform) { replyError(SGCERR_UNREACHABLE, @"platform unavailable"); return; }
        SGControlReplyBlock      replyCopy      = [reply copy];
        SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
        [platform listNativePushAppsWithCompletion:^(SGControlError err, NSData *listPayload) {
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
        reply(SGCMSG_BUNDLE_ID_LIST,
              SGCBundleIdListEncode([[SGDatabaseManager sharedManager] registeredBundleIdentifiers]));
    } forMessageType:SGCMSG_LIST_SKYGLOW_APPS];

    [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                      SGControlReplyBlock reply,
                                      SGControlReplyErrorBlock replyError) {
        if (req->payloadLength < sizeof(SGCBundleIdPayload)) {
            replyError(SGCERR_INVALID_REQUEST, @"register-input payload too short");
            return;
        }
        if (!platform) { replyError(SGCERR_UNREACHABLE, @"platform unavailable"); return; }
        NSData *payloadCopy = [NSData dataWithBytes:req->payload length:req->payloadLength];
        SGControlReplyBlock      replyCopy      = [reply copy];
        SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
        [platform registerInputAppPayload:payloadCopy completion:^(SGControlError err, NSString *detail) {
            if (err == SGCERR_OK) replyCopy(SGCMSG_GENERIC_ACK, nil);
            else replyErrorCopy(err, detail.length ? detail : @"register request failed");
            [replyCopy release];
            [replyErrorCopy release];
        }];
    } forMessageType:SGCMSG_REGISTER_INPUT_APP];
}

@end
