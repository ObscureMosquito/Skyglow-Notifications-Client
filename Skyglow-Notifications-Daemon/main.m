#import <Foundation/Foundation.h>
#import "SGDaemon.h"
#import "SGServerLocator.h"
#import "SGConfiguration.h"
#import "SGDatabaseManager.h"
#import "SGStatusServer.h"
#import "SGProtocolHandler.h"
#import "SGTokenManager.h"
#import "SGControlChannel.h"
#import "SGLog.h"
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>

static int64_t _sgDaemonStartTime = 0;

#define SG_LOG_ROTATE_BYTES (1024u * 1024u)

int main(int argc, char *argv[]) {
    @autoreleasepool {
        signal(SIGPIPE, SIG_IGN);

        SGLog_SetProcessName("SkyglowNotificationsDaemon");
        if (SGLog_OpenFile([SGPath(@"/var/log/skyglow.log") UTF8String],
                           SG_LOG_ROTATE_BYTES) != 0) {
            NSLog(@"[Skyglow] WARNING: could not open log file — running with syslog only.");
        }

        SGConfiguration *config = [SGConfiguration sharedConfiguration];
        SGLog_SetMinLevel((SGLogLevel)[config logLevel]);

        int pid_fd = open([SGPath(@"/var/run/skyglow_daemon.pid") UTF8String], O_RDWR | O_CREAT, 0666);
        if (pid_fd < 0) {
            SGLOGE(Skyglow, "FATAL: Could not create or open PID file.");
            exit(EXIT_FAILURE);
        }

        fchmod(pid_fd, 0666);

        if (flock(pid_fd, LOCK_EX | LOCK_NB) != 0) {
            SGLOGE(Skyglow, "FATAL: Another instance of Skyglow Notifications Daemon is already running! Aborting.");
            close(pid_fd);
            exit(EXIT_FAILURE);
        }

        ftruncate(pid_fd, 0);
        dprintf(pid_fd, "%d\n", getpid());

        SGLOGI(Skyglow, "Speedy Execution Is The Mother Of Good Fortune");
        SGLOGI(Skyglow, "Daemon starting (pid=%d)", (int)getpid());

        _sgDaemonStartTime = (int64_t)time(NULL);
        SGStatusServer_Start([SGPath(@"/var/run/skyglow_status.sock") UTF8String], _sgDaemonStartTime);

        signal(SIGTERM, SIG_IGN);
        dispatch_source_t sigtermSource = dispatch_source_create(
            DISPATCH_SOURCE_TYPE_SIGNAL, SIGTERM, 0, dispatch_get_main_queue());
        dispatch_source_set_event_handler(sigtermSource, ^{
            SGLOGI(Skyglow, "SIGTERM received — initiating graceful shutdown.");
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

            NSData *token = nil;
            NSError *err = nil;
            NSArray *existing = [[SGDatabaseManager sharedManager] tokenEntriesForBundleIdentifier:bundleID];
            if ([existing count] > 0) {
                NSData *t = existing[0][@"token"];
                if ([t length] > 0) token = t;
            }
            SGTokenManager *tm = nil;
            if (!token) {
                tm = [[SGTokenManager alloc] init];
                token = [tm generateTokenLocallyForBundleIdentifier:bundleID error:&err];
            }

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
            SGLOGI(Skyglow, "Control channel: TEST_INJECT received.");
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
            if (bundleID.length) {
                SGDatabaseManager *db = [SGDatabaseManager sharedManager];
                SGTokenManager *tm = [[SGTokenManager alloc] init];
                NSError *err = nil;
                NSData *tok = [tm synchronizedTokenForBundleIdentifier:bundleID error:&err];
                [tm release];
                if (!tok) {
                    SGLOGE(Skyglow, "ENABLE_APP: token mint failed for %s: %s",
                           [bundleID UTF8String], [[err description] UTF8String]);
                }
                [db setMuted:NO forBundleIdentifier:bundleID];
                SGP_FlushActiveTopicFilter();
            }
            [bundleID release];
            reply(SGCMSG_GENERIC_ACK, nil);
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
            if (bundleID.length) {
                [[SGDatabaseManager sharedManager] setMuted:YES forBundleIdentifier:bundleID];
                SGP_FlushActiveTopicFilter();
            }
            [bundleID release];
            reply(SGCMSG_GENERIC_ACK, nil);
        } forMessageType:SGCMSG_DISABLE_APP];

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
            if (bundleID.length) {
                [daemon _runDeletionCascadeForBundle:bundleID];
                SGP_FlushActiveTopicFilter();
                [daemon clearPendingDeletionForBundleIdentifier:bundleID];
            }
            [bundleID release];
            reply(SGCMSG_GENERIC_ACK, nil);
        } forMessageType:SGCMSG_DELETE_APP];

        if (![controlChannel start]) {
            SGLOGE(Skyglow, "SGControlChannel server failed to start.");
        } else {
            [daemon attachControlChannel:controlChannel];
        }

        SGControlChannel *springBoardClient =
            [[SGControlChannel clientForServiceName:SKYGLOW_CONTROL_SERVICE_SPRINGBOARD] retain];
        [springBoardClient start];
        [daemon attachSpringBoardClient:springBoardClient];

        [daemon start];

        CFRunLoopRun();

        SGLOGI(Skyglow, "SGDaemon shutting down...");
        [daemon requestGracefulDisconnect];

        [daemon attachControlChannel:nil];
        [daemon attachSpringBoardClient:nil];
        [springBoardClient stop];
        [springBoardClient release];
        [controlChannel stop];
        [controlChannel release];

        SGStatusServer_Shutdown();
        [[SGDatabaseManager sharedManager] closeDatabase];

        dispatch_source_cancel(sigtermSource);
        dispatch_release(sigtermSource);

        [daemon release];
        
        unlink([SGPath(@"/var/run/skyglow_daemon.pid") UTF8String]);
        flock(pid_fd, LOCK_UN);
        close(pid_fd);

        SGLog_Flush();
        SGLog_CloseFile();
    }
    return 0;
}
