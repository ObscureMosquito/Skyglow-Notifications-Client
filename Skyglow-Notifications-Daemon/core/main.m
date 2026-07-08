#import <Foundation/Foundation.h>
#import "SGDaemon.h"
#import "SGStateStore.h"
#import "SGCompatibilityShim.h"
#import "SGServerLocator.h"
#import "SGConfiguration.h"
#import "SGDatabaseManager.h"
#import "SGStatusServer.h"
#import "SGProtocolHandler.h"
#import "SGTokenManager.h"
#import "SGControlChannel.h"
#import "SGLog.h"
#import "SGMigration.h"
#import <TargetConditionals.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>

static int64_t _sgDaemonStartTime = 0;

#define SG_LOG_ROTATE_BYTES (1024u * 1024u)

int main(int argc, char *argv[]) {
    @autoreleasepool {
        #if TARGET_OS_IPHONE
        if (setgid(0) != 0 || setuid(0) != 0) {
            fprintf(stderr, "code=%s result=failed reason=privilege_elevation\n",
                    SGND_DAEMON_PRIVILEGE_FAILED);
            exit(EXIT_FAILURE);
        }
        #endif

        signal(SIGPIPE, SIG_IGN);

        SGNInstallCompatibilityShim();
        SGEnsureRuntimeDirectories();

        SGLog_SetProcessName("SkyglowNotificationsDaemon");
        if (SGLog_OpenFile([SGPath(SG_LOG_PATH) UTF8String],
                           SG_LOG_ROTATE_BYTES) != 0) {
            SGLOGW(Skyglow, "code=%s path=%s result=syslog_only", SGND_DAEMON_LOG_FILE_UNAVAILABLE, [SGPath(SG_LOG_PATH) UTF8String]);
        }

        if (!SGMigrationRunIfNeeded()) {
            SGLOGE(Skyglow, "code=SGN_MIGRATION_FAILED result=exiting");
            exit(EXIT_FAILURE);
        }

        SGConfiguration *config = [SGConfiguration sharedConfiguration];
        SGLog_SetMinLevel((SGLogLevel)[config logLevel]);

        int pid_fd = open([SGPath(SG_PID_PATH) UTF8String], O_RDWR | O_CREAT | O_NOFOLLOW, 0644);
        if (pid_fd < 0) {
            SGLOGE(Skyglow, "code=%s path=%s result=failed errno=%d", SGND_DAEMON_PID_FILE_FAILED, [SGPath(SG_PID_PATH) UTF8String], errno);
            exit(EXIT_FAILURE);
        }

        fchmod(pid_fd, 0644);

        if (flock(pid_fd, LOCK_EX | LOCK_NB) != 0) {
            SGLOGE(Skyglow, "code=%s path=%s result=exiting errno=%d", SGND_DAEMON_ALREADY_RUNNING, [SGPath(SG_PID_PATH) UTF8String], errno);
            close(pid_fd);
            exit(EXIT_FAILURE);
        }

        ftruncate(pid_fd, 0);
        dprintf(pid_fd, "%d\n", getpid());

        SGLOGI(Skyglow, "code=%s pid=%d result=starting", SGND_DAEMON_STARTED, (int)getpid());

        _sgDaemonStartTime = (int64_t)time(NULL);
        SGStatusServer_Start(_sgDaemonStartTime);

        signal(SIGTERM, SIG_IGN);
        dispatch_source_t sigtermSource = dispatch_source_create(
            DISPATCH_SOURCE_TYPE_SIGNAL, SIGTERM, 0, dispatch_get_main_queue());
        dispatch_source_set_event_handler(sigtermSource, ^{
            SGLOGI(Skyglow, "code=%s signal=SIGTERM action=stop_runloop", SGND_DAEMON_SHUTDOWN_REQUESTED);
            CFRunLoopStop(CFRunLoopGetMain());
        });
        dispatch_resume(sigtermSource);

        SGDaemon *daemon = [[SGDaemon alloc] init];
        SGP_SetDelegate(daemon);

        SGControlChannel *controlChannel =
            [[SGControlChannel serverWithServiceName:SKYGLOW_CONTROL_SERVICE_DAEMON] retain];

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

            NSString *bundleRet = [bundleID retain];
            SGControlReplyBlock replyCopy = [reply copy];
            SGControlReplyErrorBlock replyErrorCopy = [replyError copy];

            [daemon dispatchResetRegistrationForBundleIdentifier:bundleRet
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
            SGControlChannel *sb = [daemon springBoardClient];
            if (!sb) { replyError(SGCERR_UNREACHABLE, @"SpringBoard channel not attached"); return; }
            SGControlReplyBlock      replyCopy      = [reply copy];
            SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
            [sb sendRequest:SGCMSG_LIST_PUSH_REGISTERED_APPS
                    payload:nil
                    timeout:0
                 completion:^(SGControlError err, const SGControlChannelMessage *response) {
                if (err == SGCERR_OK && response) {
                    NSData *body = [NSData dataWithBytes:response->payload
                                                  length:response->payloadLength];
                    replyCopy(SGCMSG_BUNDLE_ID_LIST, body);
                } else {
                    replyErrorCopy(err, (err == SGCERR_TIMEOUT || err == SGCERR_UNREACHABLE)
                        ? @"SpringBoard did not respond"
                        : @"SpringBoard rejected the list request");
                }
                [replyCopy release];
                [replyErrorCopy release];
            }];
        } forMessageType:SGCMSG_LIST_PUSH_REGISTERED_APPS];

        [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                          SGControlReplyBlock reply,
                                          SGControlReplyErrorBlock replyError) {
            if (req->payloadLength < sizeof(SGCBundleIdPayload)) {
                replyError(SGCERR_INVALID_REQUEST, @"register-input payload too short");
                return;
            }
            SGControlChannel *sb = [daemon springBoardClient];
            if (!sb) { replyError(SGCERR_UNREACHABLE, @"SpringBoard channel not attached"); return; }
            NSData *payloadCopy = [NSData dataWithBytes:req->payload length:req->payloadLength];
            SGControlReplyBlock      replyCopy      = [reply copy];
            SGControlReplyErrorBlock replyErrorCopy = [replyError copy];
            [sb sendRequest:SGCMSG_REGISTER_INPUT_APP
                    payload:payloadCopy
                    timeout:0
                 completion:^(SGControlError err, const SGControlChannelMessage *response) {
                if (err == SGCERR_OK) {
                    replyCopy(SGCMSG_GENERIC_ACK, nil);
                } else {
                    NSString *detail = nil;
                    if (response && response->messageType == SGCMSG_ERROR_RESPONSE &&
                        response->payloadLength >= sizeof(SGCErrorResponsePayload)) {
                        SGCErrorResponsePayload *ep = (SGCErrorResponsePayload *)response->payload;
                        detail = [[[NSString alloc] initWithBytes:ep->message
                                                           length:strnlen(ep->message, sizeof(ep->message))
                                                         encoding:NSUTF8StringEncoding] autorelease];
                    }
                    if (!detail.length) {
                        detail = (err == SGCERR_TIMEOUT || err == SGCERR_UNREACHABLE)
                            ? @"SpringBoard did not respond"
                            : @"SpringBoard rejected the register request";
                    }
                    replyErrorCopy(err, detail);
                }
                [replyCopy release];
                [replyErrorCopy release];
            }];
        } forMessageType:SGCMSG_REGISTER_INPUT_APP];

        if (![controlChannel start]) {
            SGLOGE(Skyglow, "code=%s service=%s result=failed", SGND_DAEMON_CONTROL_START_FAILED, SKYGLOW_CONTROL_SERVICE_DAEMON);
        } else {
            [daemon attachControlChannel:controlChannel];
        }

        SGControlChannel *springBoardClient =
            [[SGControlChannel clientForServiceName:SKYGLOW_CONTROL_SERVICE_SPRINGBOARD] retain];
        [springBoardClient start];
        [daemon attachSpringBoardClient:springBoardClient];

        [daemon.stateStore drainDurableEventInbox];
        [daemon start];

        CFRunLoopRun();

        SGLOGI(Skyglow, "code=%s pid=%d result=stopping", SGND_DAEMON_SHUTTING_DOWN, (int)getpid());
        [daemon requestGracefulDisconnect];

        [daemon attachControlChannel:nil];
        [daemon attachSpringBoardClient:nil];
        [springBoardClient stop];
        [springBoardClient release];
        [controlChannel stop];
        [controlChannel release];

        [[SGDatabaseManager sharedManager] closeDatabase];

        dispatch_source_cancel(sigtermSource);
        dispatch_release(sigtermSource);

        [daemon release];
        
        unlink([SGPath(SG_PID_PATH) UTF8String]);
        flock(pid_fd, LOCK_UN);
        close(pid_fd);

        SGLog_Flush();
        SGLog_CloseFile();
    }
    return 0;
}
