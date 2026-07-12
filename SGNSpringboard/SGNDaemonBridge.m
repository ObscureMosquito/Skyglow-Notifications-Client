#import "SGNDaemonBridge.h"
#import "SGNPrivateAPI.h"
#import "SGNAppIntent.h"
#import "SGNNativePush.h"
#import "SGNNativePushBroker.h"
#import "SGControlChannel.h"
#import "SGControlChannelProtocol.h"
#import "SGControlPayloadCodec.h"
#import "SGSharedConstants.h"
#import "SGDurableInbox.h"
#import <objc/runtime.h>
#import <objc/message.h>

static SGControlChannel *gSGCDaemonClient = nil;
static SGControlChannel *gSGCSBServer     = nil;

static NSString *SGNBundleIdentifierFromRequest(
    const SGControlChannelMessage *request) {
    if (!request || request->payloadLength < sizeof(SGCBundleIdPayload)) {
        return nil;
    }
    const SGCBundleIdPayload *payload =
        (const SGCBundleIdPayload *)request->payload;
    NSString *bundleIdentifier = [[[NSString alloc]
        initWithBytes:payload->bundleID
               length:strnlen(payload->bundleID, sizeof(payload->bundleID))
             encoding:NSUTF8StringEncoding] autorelease];
    return SG_IsIdentifierStringSafe(bundleIdentifier) ? bundleIdentifier : nil;
}

static void SGNCopyCString(char *dst, size_t dstSize, const char *src) {
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

static NSString *SGNControlErrorDetail(
    const SGControlChannelMessage *response) {
    if (!response || response->messageType != SGCMSG_ERROR_RESPONSE ||
        response->payloadLength < sizeof(SGCErrorResponsePayload)) {
        return nil;
    }
    const SGCErrorResponsePayload *payload =
        (const SGCErrorResponsePayload *)response->payload;
    return [[[NSString alloc]
        initWithBytes:payload->message
               length:strnlen(payload->message, sizeof(payload->message))
             encoding:NSUTF8StringEncoding] autorelease];
}

#pragma mark - Commands to the daemon

void SGNSendBundleCommand(SGControlMessageType messageType,
                          NSString *bundleId,
                          NSString *inboxEventPathToRemove) {
    if (!bundleId.length) return;
    if (!gSGCDaemonClient) return;

    SGCBundleIdPayload payload;
    memset(&payload, 0, sizeof(payload));
    SGNCopyCString(payload.bundleID, sizeof(payload.bundleID), [bundleId UTF8String]);

    NSString *eventPathCopy = [inboxEventPathToRemove copy];
    [gSGCDaemonClient sendRequest:messageType
                          payload:[NSData dataWithBytes:&payload length:sizeof(payload)]
                          timeout:SG_CONTROL_DELETE_APP_TIMEOUT_SEC
                       completion:^(SGControlError error,
                                    const SGControlChannelMessage *response) {
        if (error == SGCERR_OK && eventPathCopy) {
            NSDictionary *event = [NSDictionary dictionaryWithObject:eventPathCopy
                forKey:SGDurableEventFilePathKey];
            if (!SGDurableEventRemove(event)) {
                NSLog(@"[SGN] Applied uninstall but could not remove inbox event %@",
                      [eventPathCopy lastPathComponent]);
            }
        }
        [eventPathCopy release];
    }];
}

void SGNSendDeleteAppCommand(NSString *bundleId) {
    if (!bundleId.length) return;
    SGNSetRuntimeAppIntent(bundleId, NO);

    NSError *enqueueError = nil;
    NSString *eventPath = SGDurableEventEnqueueDeleteApp(
        SGNPath(SG_DURABLE_EVENT_INBOX_PATH),
        bundleId, &enqueueError);
    if (!eventPath) {
        /* The daemon owns persistent app state.  If the missed-uninstall inbox
         * cannot be recorded, still try live IPC, but do not mutate the daemon
         * prefs plist from SpringBoard. */
        NSLog(@"[SGN] Durable uninstall enqueue failed for %@: %@; continuing with live IPC only",
              bundleId, enqueueError);
    }

    SGNSendBundleCommand(SGCMSG_DELETE_APP, bundleId, eventPath);
}

#pragma mark - Startup reconciliation

static NSSet *SGNMissingPersistedApplications(void) {
    SBApplicationController *controller =
        [objc_getClass("SBApplicationController") sharedInstance];
    BOOL lookupAvailable =
        [controller respondsToSelector:@selector(applicationWithBundleIdentifier:)] ||
        [controller respondsToSelector:@selector(applicationWithDisplayIdentifier:)];
    if (!controller || !lookupAvailable) return nil;

    NSDictionary *preferences =
        [NSDictionary dictionaryWithContentsOfFile:kPrefsPlistPath];
    NSDictionary *appStatus = [preferences objectForKey:@"appStatus"];
    if (![appStatus isKindOfClass:[NSDictionary class]]) return [NSSet set];

    NSMutableSet *missing = [NSMutableSet set];
    for (id bundleId in appStatus) {
        if (![bundleId isKindOfClass:[NSString class]] ||
            !SG_IsIdentifierStringSafe(bundleId)) {
            continue;
        }
        if (!SBApp_LookupByIdentifier(bundleId)) {
            [missing addObject:bundleId];
        }
    }
    return missing;
}

void SGNScheduleInstalledApplicationReconciliation(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10ull * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        NSSet *firstPass = [SGNMissingPersistedApplications() copy];
        if (!firstPass) {
            NSLog(@"[SGN] Installed-application reconciliation unavailable on this OS");
            return;
        }
        if ([firstPass count] == 0) {
            [firstPass release];
            return;
        }

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10ull * NSEC_PER_SEC),
                       dispatch_get_main_queue(), ^{
            NSSet *secondPass = SGNMissingPersistedApplications();
            if (secondPass) {
                for (NSString *bundleId in firstPass) {
                    if (![secondPass containsObject:bundleId]) continue;
                    NSLog(@"[SGN] Recovering missed uninstall for %@", bundleId);
                    SGNSendDeleteAppCommand(bundleId);
                }
            }
            [firstPass release];
        });
    });
}

#pragma mark - Token fetch + failure delivery

id SGN_RemoteAppForBundle(NSString *bundleId) {
    id app = SBApp_LookupByIdentifier(bundleId);
    if (!app || ![app respondsToSelector:@selector(remoteApplication)]) return nil;
    return [app performSelector:@selector(remoteApplication)];
}

static void SGN_DeliverFailure(NSString *bundleId, NSString *reason) {
    id remoteApp = SGN_RemoteAppForBundle(bundleId);
    if (!remoteApp) return;

    NSDictionary *info = reason
        ? [NSDictionary dictionaryWithObject:reason forKey:NSLocalizedDescriptionKey]
        : nil;
    NSError *err = [NSError errorWithDomain:@"com.skyglow.sgn" code:-1 userInfo:info];

    SEL sel = @selector(remoteNotificationRegistrationFailedWithError:);
    if ([remoteApp respondsToSelector:sel]) {
        [remoteApp performSelector:sel withObject:err];
        return;
    }
    SEL altSel = NSSelectorFromString(@"_remoteNotificationRegistrationFailedWithError:");
    if ([remoteApp respondsToSelector:altSel]) {
        [remoteApp performSelector:altSel withObject:err];
        return;
    }
    NSLog(@"[SGN] No failure selector available on remoteApp for %@", bundleId);
}

void SGN_AsyncFetchAndDeliverToken(NSString *bundleId,
                                   id application,
                                   id environment,
                                   int notificationTypes,
                                   void (^completion)(SGControlError,
                                                      NSString *)) {
    NSString *safeBundleId = [bundleId copy];
    id        safeApp      = application ? [application retain] : nil;
    id        safeEnv      = environment ? [environment retain] : nil;
    void (^completionCopy)(SGControlError, NSString *) = [completion copy];

    if (!gSGCDaemonClient) {
        NSLog(@"[SGN] AsyncFetch: control channel not initialised for %@", safeBundleId);
        dispatch_async(dispatch_get_main_queue(), ^{
            SGN_DeliverFailure(safeBundleId, @"control channel not initialised");
            if (completionCopy) completionCopy(SGCERR_UNREACHABLE,
                @"control channel not initialised");
            [safeBundleId release];
            [safeApp release];
            [safeEnv release];
            [completionCopy release];
        });
        return;
    }

    SGCTokenRequestPayload payload;
    memset(&payload, 0, sizeof(payload));
    SGNCopyCString(payload.bundleID, sizeof(payload.bundleID), [safeBundleId UTF8String]);
    NSData *payloadData = [NSData dataWithBytes:&payload length:sizeof(payload)];

    [gSGCDaemonClient sendRequest:SGCMSG_TOKEN_REQUEST
                          payload:payloadData
                          timeout:0
                       completion:^(SGControlError err, const SGControlChannelMessage *response) {
        NSData *token = nil;
        SGControlError result = err;
        NSString *detail = SGNControlErrorDetail(response);
        if (err == SGCERR_OK && response &&
            response->payloadLength >= sizeof(SGCTokenResponsePayload)) {
            SGCTokenResponsePayload *resp = (SGCTokenResponsePayload *)response->payload;
            if (resp->tokenLength > 0 && resp->tokenLength <= SG_CONTROL_MAX_TOKEN_SIZE) {
                token = [NSData dataWithBytes:resp->tokenData length:resp->tokenLength];
            }
        }
        if (!token && result == SGCERR_OK) {
            result = SGCERR_INTERNAL;
            detail = @"daemon returned an invalid Skyglow token";
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            SGControlError finalResult = result;
            NSString *finalDetail = detail;
            if (token) {
                @try {
                    SGN_DeliverSuccess(safeBundleId, safeApp, safeEnv,
                                       notificationTypes, token);
                } @catch (NSException *e) {
                    NSLog(@"[SGN] Delivery exception for %@: %@", safeBundleId, e);
                    finalResult = SGCERR_INTERNAL;
                    finalDetail = [e reason] ?: @"token delivery exception";
                }
            } else {
                finalDetail = [detail length] ? detail :
                    [NSString stringWithFormat:@"token request failed (err=%d)",
                                               result];
                SGN_DeliverFailure(safeBundleId, finalDetail);
            }
            if (completionCopy) completionCopy(finalResult, finalDetail);
            [safeBundleId release];
            [safeApp release];
            [safeEnv release];
            [completionCopy release];
        });
    }];
}

#pragma mark - Notification Delivery

static NSDictionary *WrapInAPNSFormat(NSDictionary *flat) {
    if ([flat[@"aps"] isKindOfClass:[NSDictionary class]]) {
        return flat;
    }

    NSMutableDictionary *alert = [NSMutableDictionary dictionary];
    if (flat[@"title"]) [alert setObject:flat[@"title"] forKey:@"title"];
    if (flat[@"body"])  [alert setObject:flat[@"body"]  forKey:@"body"];

    NSMutableDictionary *aps = [NSMutableDictionary dictionary];
    if (alert.count > 0) [aps setObject:alert forKey:@"alert"];
    if (flat[@"sound"])    [aps setObject:flat[@"sound"] forKey:@"sound"];
    if (flat[@"badge"])    [aps setObject:flat[@"badge"] forKey:@"badge"];
    if (flat[@"category"]) [aps setObject:flat[@"category"] forKey:@"category"];
    id contentAvailable = flat[@"content-available"] ?: flat[@"content_available"];
    if (contentAvailable) [aps setObject:contentAvailable forKey:@"content-available"];

    NSMutableDictionary *result = [NSMutableDictionary dictionaryWithObject:aps forKey:@"aps"];
    for (id key in flat) {
        if (![key isKindOfClass:[NSString class]]) continue;
        if ([key isEqualToString:@"title"] || [key isEqualToString:@"body"] ||
            [key isEqualToString:@"sound"] || [key isEqualToString:@"badge"] ||
            [key isEqualToString:@"category"] || [key isEqualToString:@"aps"] ||
            [key isEqualToString:@"content-available"] ||
            [key isEqualToString:@"content_available"]) continue;
        [result setObject:flat[key] forKey:key];
    }
    return result;
}

static void SGNFinishPushDelivery(
    SGControlError error,
    NSString *detail,
    NSString *topic,
    NSDictionary *userInfo,
    SGControlReplyBlock reply,
    SGControlReplyErrorBlock replyError) {
    if (error == SGCERR_OK) {
        reply(SGCMSG_GENERIC_ACK, nil);
    } else {
        replyError(error, detail ?: @"push delivery failed");
    }
    [topic release];
    [userInfo release];
    [reply release];
    [replyError release];
}

#pragma mark - SGControlChannel Server (push delivery + prefs commands)

void StartSpringBoardControlChannel(void) {
    gSGCSBServer = [[SGControlChannel serverWithServiceName:SKYGLOW_CONTROL_SERVICE_SPRINGBOARD] retain];

    [gSGCSBServer registerHandler:^(const SGControlChannelMessage *req,
                                    SGControlReplyBlock reply,
                                    SGControlReplyErrorBlock replyError) {
        if (req->payloadLength < offsetof(SGCPushDeliveryPayload, userInfoData)) {
            replyError(SGCERR_INVALID_REQUEST, @"push delivery payload too short");
            return;
        }
        SGCPushDeliveryPayload *pd = (SGCPushDeliveryPayload *)req->payload;
        NSString *topic = [[NSString alloc] initWithBytes:pd->bundleID
                                                   length:strnlen(pd->bundleID, sizeof(pd->bundleID))
                                                 encoding:NSUTF8StringEncoding];
        if (!SG_IsIdentifierStringSafe(topic)) {
            [topic release];
            replyError(SGCERR_INVALID_REQUEST, @"push delivery bundle id invalid");
            return;
        }
        NSDictionary *userInfo = nil;
        if (pd->userInfoLength > SG_CONTROL_MAX_USERINFO_SIZE) {
            [topic release];
            replyError(SGCERR_INVALID_REQUEST, @"push delivery userInfo too large");
            return;
        }
        if (pd->userInfoLength > 0) {
            size_t innerNeeded = (size_t)pd->userInfoLength + offsetof(SGCPushDeliveryPayload, userInfoData);
            if (innerNeeded > req->payloadLength) {
                [topic release];
                replyError(SGCERR_INVALID_REQUEST, @"push delivery userInfo length exceeds payload");
                return;
            }
            NSData *data = [NSData dataWithBytes:pd->userInfoData length:pd->userInfoLength];
            userInfo = [NSPropertyListSerialization propertyListWithData:data
                                                                 options:NSPropertyListImmutable
                                                                  format:NULL error:NULL];
            // Parse failure or a non-dictionary root means the payload was damaged in transit
            if (![userInfo isKindOfClass:[NSDictionary class]]) {
                [topic release];
                replyError(SGCERR_INVALID_REQUEST, @"push delivery userInfo not a plist dictionary");
                return;
            }
        }

        SGControlReplyBlock      replyCopy      = [reply copy];
        SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
        NSDictionary            *userInfoRet    = [userInfo retain];

        dispatch_async(dispatch_get_main_queue(), ^{
            NSLog(@"[SGN] Delivering push for topic: %@", topic);
            NSDictionary *apnsPayload =
                WrapInAPNSFormat(userInfoRet ?: @{});
            @try {
                [[SGNNativePushBroker sharedBroker]
                    deliverAPNSPayload:apnsPayload
                    toBundleIdentifier:topic
                    completion:^(SGControlError error, NSString *detail) {
                        SGNFinishPushDelivery(error, detail, topic,
                                              userInfoRet, replyCopy,
                                              replyErrorCopy);
                    }];
            } @catch (NSException *exception) {
                NSLog(@"[SGN] Push delivery backend threw: %@", exception);
                SGNFinishPushDelivery(SGCERR_INTERNAL,
                    [exception reason] ?: @"notification backend exception",
                    topic, userInfoRet, replyCopy, replyErrorCopy);
            }
        });
    } forMessageType:SGCMSG_PUSH_DELIVERY];

    [gSGCSBServer registerHandler:^(const SGControlChannelMessage *req,
                                    SGControlReplyBlock reply,
                                    SGControlReplyErrorBlock replyError) {
        if (req->payloadLength < sizeof(SGCBundleIdPayload)) {
            replyError(SGCERR_INVALID_REQUEST, @"register input payload too short");
            return;
        }
        SGCBundleIdPayload *bp = (SGCBundleIdPayload *)req->payload;
        NSString *bundleId = [[NSString alloc] initWithBytes:bp->bundleID
                                                      length:strnlen(bp->bundleID, sizeof(bp->bundleID))
                                                    encoding:NSUTF8StringEncoding];
        if (!SG_IsIdentifierStringSafe(bundleId)) {
            [bundleId release];
            replyError(SGCERR_INVALID_REQUEST, @"register input bundle id invalid");
            return;
        }

        NSString *bundleIdRet = [bundleId retain];
        SGControlReplyBlock      replyCopy      = [reply copy];
        SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
        dispatch_async(dispatch_get_main_queue(), ^{
            [[SGNNativePushBroker sharedBroker]
                activateSkyglowForBundleIdentifier:bundleIdRet
                completion:^(SGControlError error, NSString *detail) {
                    if (error == SGCERR_OK) {
                        replyCopy(SGCMSG_GENERIC_ACK, nil);
                    } else {
                        replyErrorCopy(error,
                            detail ?: @"Skyglow activation failed");
                    }
                    [bundleIdRet release];
                    [replyCopy release];
                    [replyErrorCopy release];
                }];
        });
        [bundleId release];
    } forMessageType:SGCMSG_REGISTER_INPUT_APP];

    [gSGCSBServer registerHandler:^(const SGControlChannelMessage *req,
                                    SGControlReplyBlock reply,
                                    SGControlReplyErrorBlock replyError) {
        SGControlReplyBlock replyCopy = [reply copy];
        SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
        dispatch_async(dispatch_get_main_queue(), ^{
            SGControlError error = SGCERR_OK;
            NSString *detail = nil;
            NSArray *identifiers = [[SGNNativePushBroker sharedBroker]
                registeredBundleIdentifiersWithError:&error detail:&detail];
            if (error == SGCERR_OK) {
                replyCopy(SGCMSG_BUNDLE_ID_LIST,
                          SGCBundleIdListEncode(identifiers));
            } else {
                replyErrorCopy(error, detail ?: @"native push query failed");
            }
            [replyCopy release];
            [replyErrorCopy release];
        });
    } forMessageType:SGCMSG_LIST_NATIVE_PUSH_APPS];

    [gSGCSBServer registerHandler:^(const SGControlChannelMessage *req,
                                    SGControlReplyBlock reply,
                                    SGControlReplyErrorBlock replyError) {
        NSString *bundleId = SGNBundleIdentifierFromRequest(req);
        if (!bundleId) {
            replyError(SGCERR_INVALID_REQUEST, @"reset registration bundle id invalid");
            return;
        }
        NSString *bidForReset = [bundleId copy];
        SGControlReplyBlock replyCopy = [reply copy];
        SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
        dispatch_async(dispatch_get_main_queue(), ^{
            SGN_DeregisterAppNativelyWithCompletion(bidForReset,
                ^(SGControlError error, NSString *detail) {
                    if (error == SGCERR_OK) {
                        replyCopy(SGCMSG_GENERIC_ACK, nil);
                    } else {
                        replyErrorCopy(error, detail ?: @"native reset failed");
                    }
                    [bidForReset release];
                    [replyCopy release];
                    [replyErrorCopy release];
                });
        });
    } forMessageType:SGCMSG_RESET_APP_REGISTRATION];

    [gSGCSBServer registerHandler:^(const SGControlChannelMessage *req,
                                    SGControlReplyBlock reply,
                                    SGControlReplyErrorBlock replyError) {
        NSString *bundleId = SGNBundleIdentifierFromRequest(req);
        if (!bundleId) {
            replyError(SGCERR_INVALID_REQUEST,
                       @"native registration bundle id invalid");
            return;
        }
        NSString *bidForRegistration = [bundleId copy];
        SGControlReplyBlock replyCopy = [reply copy];
        SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
        dispatch_async(dispatch_get_main_queue(), ^{
            SGN_RegisterAppNativelyWithCompletion(bidForRegistration,
                ^(SGControlError error, NSString *detail) {
                    if (error == SGCERR_OK) {
                        replyCopy(SGCMSG_GENERIC_ACK, nil);
                    } else {
                        replyErrorCopy(error,
                            detail ?: @"native registration failed");
                    }
                    [bidForRegistration release];
                    [replyCopy release];
                    [replyErrorCopy release];
                });
        });
    } forMessageType:SGCMSG_REGISTER_NATIVE_PUSH_APP];

    [gSGCSBServer registerHandler:^(const SGControlChannelMessage *req,
                                    SGControlReplyBlock reply,
                                    SGControlReplyErrorBlock replyError) {
        NSString *bundleId = SGNBundleIdentifierFromRequest(req);
        if (!bundleId) {
            replyError(SGCERR_INVALID_REQUEST,
                       @"native authorization bundle id invalid");
            return;
        }
        NSString *bundleCopy = [bundleId copy];
        SGControlReplyBlock replyCopy = [reply copy];
        SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *detail = nil;
            SGControlError error = [[SGNNativePushBroker sharedBroker]
                beginAuthorizationForBundleIdentifier:bundleCopy
                detail:&detail];
            if (error == SGCERR_OK) {
                /* The user decision is intentionally not part of this reply:
                 * a permission sheet may remain open beyond the IPC timeout. */
                replyCopy(SGCMSG_GENERIC_ACK, nil);
            } else {
                replyErrorCopy(error,
                    detail ?: @"native authorization request failed");
            }
            [bundleCopy release];
            [replyCopy release];
            [replyErrorCopy release];
        });
    } forMessageType:SGCMSG_AUTHORIZE_NATIVE_PUSH_APP];

    if (![gSGCSBServer start]) {
        NSLog(@"[SGN] SGControlChannel server failed to start on %s", SKYGLOW_CONTROL_SERVICE_SPRINGBOARD);
        [gSGCSBServer release];
        gSGCSBServer = nil;
    }
}

void StartDaemonControlChannelClient(void) {
    gSGCDaemonClient = [[SGControlChannel clientForServiceName:SKYGLOW_CONTROL_SERVICE_DAEMON] retain];
    [gSGCDaemonClient start];
}
