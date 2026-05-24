#import <Foundation/Foundation.h>
#import "SGDaemon.h"
#import "SGReachabilityMonitor.h"
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
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/IOMessage.h>

static int64_t _sgDaemonStartTime = 0;

/**
 * Rotation threshold for /var/log/skyglow.log.  1 MB × 2 generations keeps
 * roughly 8–24 hours of typical traffic on disk without unbounded growth.
 * Bump if Debug/Trace logging becomes a routine diagnostic posture.
 */
#define SG_LOG_ROTATE_BYTES (1024u * 1024u)

/**
 * Brief pause between broadcasting SGStateDisabled and tearing down the
 * status server when the daemon launches in a disabled-by-config state.
 * Gives any prefs UI / sntool watcher a chance to read the definitive state
 * before the socket disappears; below human-perceptible latency.
 */
#define SG_DISABLED_BROADCAST_GRACE_USEC  (200u * 1000u)

static io_connect_t          _sgPowerRootPort  = MACH_PORT_NULL;
static io_object_t           _sgPowerNotifier  = MACH_PORT_NULL;
static IONotificationPortRef _sgPowerNotifyPort = NULL;

/**
 * IOKit power notification callback.
 *
 * kIOMessageSystemHasPoweredOn fires after the system has fully woken from
 * deep sleep — display on, network stack reinitialised. We forward this to the
 * daemon as SGEventSystemDidWake, which only acts if the FSM is in
 * SGStateIdleCircuitOpen (circuit breaker tripped). From all other states it
 * is a no-op, so this fires cheaply on every wake.
 *
 * Sleep messages (CanSleep / WillSleep) must be acknowledged promptly;
 * we always allow sleep — the daemon holds no resources that prevent it.
 */
static void SG_IOPowerCallback(void *refcon, io_service_t service,
                                natural_t messageType, void *messageArgument) {
    switch (messageType) {
        case kIOMessageSystemHasPoweredOn: {
            SGDaemon *daemon = (__bridge SGDaemon *)refcon;
            [daemon handleSystemWake];
            break;
        }
        case kIOMessageCanSystemSleep:
        case kIOMessageSystemWillSleep:
            /* Always allow sleep — acknowledge immediately. */
            IOAllowPowerChange(_sgPowerRootPort, (long)messageArgument);
            break;
        default:
            break;
    }
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        signal(SIGPIPE, SIG_IGN);

        /**
         * Bring up logging before anything else can log.  SGLog_Write is
         * safe to call before SGLog_OpenFile (it falls back to syslog
         * only), but doing this first means every line — including the
         * banner and the PID-file errors — lands in /var/log/skyglow.log
         * for later inspection from the prefs UI.
         */
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

        /**
         * Start the status server BEFORE the enabled check so the preference
         * bundle always gets a definitive SGStateDisabled instead of having to
         * rely on the ambiguous PID-file-alive heuristic.
         */
        _sgDaemonStartTime = (int64_t)time(NULL);
        SGStatusServer_Start([SGPath(@"/var/run/skyglow_status.sock") UTF8String], _sgDaemonStartTime);

        if (!config.isEnabled) {
            SGLOGI(Skyglow, "Daemon is disabled. Broadcasting state and exiting.");
            SGStatusServer_Post(SGStateDisabled, 0, 0, NULL, "Daemon is disabled", 0);
            usleep(SG_DISABLED_BROADCAST_GRACE_USEC);
            SGStatusServer_Shutdown();
            unlink([SGPath(@"/var/run/skyglow_daemon.pid") UTF8String]);
            flock(pid_fd, LOCK_UN);
            close(pid_fd);
            SGLog_CloseFile();
            exit(EXIT_SUCCESS);
        }
        
        /**
         * Graceful SIGTERM handler.
         * When launchd stops the daemon, SIGTERM is sent. Without this, the process
         * dies immediately — no C_DISCONNECT is sent to the server and it must wait
         * for a TCP timeout to reclaim the slot. The dispatch source catches SIGTERM
         * on the main queue and stops the run loop cleanly, allowing the shutdown
         * path below (requestGracefulDisconnect) to execute normally.
         */
        signal(SIGTERM, SIG_IGN); // Hand SIGTERM to GCD, not the default kill handler
        dispatch_source_t sigtermSource = dispatch_source_create(
            DISPATCH_SOURCE_TYPE_SIGNAL, SIGTERM, 0, dispatch_get_main_queue());
        dispatch_source_set_event_handler(sigtermSource, ^{
            SGLOGI(Skyglow, "SIGTERM received — initiating graceful shutdown.");
            CFRunLoopStop(CFRunLoopGetMain());
        });
        dispatch_resume(sigtermSource);

        SGDaemon *daemon = [[SGDaemon alloc] init];
        SGP_SetDelegate(daemon);

        /* Register handlers before -start so an incoming request can't race a
         * missing dispatch entry. */
        SGControlChannel *controlChannel =
            [[SGControlChannel serverWithServiceName:SKYGLOW_CONTROL_SERVICE_DAEMON] retain];

        /* SGCMSG_TOKEN_REQUEST — mint or return a cached push token. */
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

            if (![[SGConfiguration sharedConfiguration] isEnabled]) {
                replyError(SGCERR_DAEMON_DISABLED, @"Daemon disabled in Settings");
                [bundleID release];
                return;
            }

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

            /* Push the token to the server asynchronously — never blocks the response. */
            if (tm) {
                NSString *bid = [bundleID retain];
                SGTokenManager *tmRetained = [tm retain];
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                    [tmRetained uploadTokenIfNeededForBundleIdentifier:bid];
                    [tmRetained release];
                    [bid release];
                });
                [tm release];
            }
            [bundleID release];
        } forMessageType:SGCMSG_TOKEN_REQUEST];

        /* SGCMSG_TOKEN_REVOKE — drop a token, notify the server. */
        [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                          SGControlReplyBlock reply,
                                          SGControlReplyErrorBlock replyError) {
            if (req->payloadLength < sizeof(SGCTokenRequestPayload)) {
                replyError(SGCERR_INVALID_REQUEST, @"token revoke payload too short");
                return;
            }
            SGCTokenRequestPayload *tReq = (SGCTokenRequestPayload *)req->payload;
            NSString *bundleID = [[NSString alloc] initWithBytes:tReq->bundleID
                                                          length:strnlen(tReq->bundleID, sizeof(tReq->bundleID))
                                                        encoding:NSUTF8StringEncoding];
            SGTokenManager *tm = [[SGTokenManager alloc] init];
            [tm revokeTokenForBundleIdentifier:bundleID reason:@"client_revoke"];
            [tm release];
            [bundleID release];
            reply(SGCMSG_GENERIC_ACK, nil);
        } forMessageType:SGCMSG_TOKEN_REVOKE];

        /* SGCMSG_FEEDBACK — app-state hint (uninstall, force-quit) from the SB tweak. */
        [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                          SGControlReplyBlock reply,
                                          SGControlReplyErrorBlock replyError) {
            if (req->payloadLength < sizeof(SGCFeedbackPayload)) {
                replyError(SGCERR_INVALID_REQUEST, @"feedback payload too short");
                return;
            }
            SGCFeedbackPayload *fb = (SGCFeedbackPayload *)req->payload;
            NSString *bundleID = [[NSString alloc] initWithBytes:fb->bundleID
                                                          length:strnlen(fb->bundleID, sizeof(fb->bundleID))
                                                        encoding:NSUTF8StringEncoding];
            NSString *reason = [[NSString alloc] initWithBytes:fb->reason
                                                        length:strnlen(fb->reason, sizeof(fb->reason))
                                                      encoding:NSUTF8StringEncoding];
            SGTokenManager *tm = [[SGTokenManager alloc] init];
            [tm revokeTokenForBundleIdentifier:bundleID reason:reason];
            [tm release];
            [bundleID release];
            [reason release];
            reply(SGCMSG_GENERIC_ACK, nil);
        } forMessageType:SGCMSG_FEEDBACK];

        /* SGCMSG_RELOAD_CONFIG — replaces com.skyglow.sgn.reload_config Darwin notification. */
        [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                          SGControlReplyBlock reply,
                                          SGControlReplyErrorBlock replyError) {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                @autoreleasepool { [daemon handleConfigurationReloadRequest]; }
            });
            reply(SGCMSG_GENERIC_ACK, nil);
        } forMessageType:SGCMSG_RELOAD_CONFIG];

        /* SGCMSG_TEST_INJECT — debug hook.  Logs receipt; no behaviour wired yet. */
        [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                          SGControlReplyBlock reply,
                                          SGControlReplyErrorBlock replyError) {
            SGLOGI(Skyglow, "Control channel: TEST_INJECT received.");
            reply(SGCMSG_GENERIC_ACK, nil);
        } forMessageType:SGCMSG_TEST_INJECT];

        /* SGCMSG_READINESS_PROBE — lets a client confirm wire compatibility + liveness. */
        [controlChannel registerHandler:^(const SGControlChannelMessage *req,
                                          SGControlReplyBlock reply,
                                          SGControlReplyErrorBlock replyError) {
            SGStatusPayload current;
            SGStatusServer_Current(&current);
            SGCReadinessResponsePayload resp;
            memset(&resp, 0, sizeof(resp));
            resp.daemonState     = (uint8_t)current.state;
            resp.protocolVersion = SG_CONTROL_VERSION;
            resp.uptime          = (uint32_t)((int64_t)time(NULL) - _sgDaemonStartTime);
            reply(SGCMSG_READINESS_RESPONSE, [NSData dataWithBytes:&resp length:sizeof(resp)]);
        } forMessageType:SGCMSG_READINESS_PROBE];

        if (![controlChannel start]) {
            SGLOGE(Skyglow, "SGControlChannel server failed to start.");
        } else {
            [daemon attachControlChannel:controlChannel];
        }

        SGControlChannel *springBoardClient =
            [[SGControlChannel clientForServiceName:SKYGLOW_CONTROL_SERVICE_SPRINGBOARD] retain];
        [springBoardClient start];
        [daemon attachSpringBoardClient:springBoardClient];

        /**
         * IOKit power notification registration.
         * Fires SGEventSystemDidWake when the device wakes from deep sleep.
         * This breaks the daemon out of SGStateIdleCircuitOpen (circuit breaker
         * tripped after 14 consecutive failures) so it retries on wake rather than
         * sitting idle until the user cycles WiFi.
         *
         * We must acknowledge CanSleep/WillSleep messages promptly; the callback
         * above always calls IOAllowPowerChange for those.
         */
        _sgPowerRootPort = IORegisterForSystemPower((__bridge void *)daemon,
                                                    &_sgPowerNotifyPort,
                                                    SG_IOPowerCallback,
                                                    &_sgPowerNotifier);
        if (_sgPowerRootPort != MACH_PORT_NULL) {
            CFRunLoopAddSource(CFRunLoopGetMain(),
                               IONotificationPortGetRunLoopSource(_sgPowerNotifyPort),
                               kCFRunLoopDefaultMode);
            SGLOGI(Skyglow, "IOKit power notifications registered.");
        } else {
            SGLOGW(Skyglow, "IOKit power notification registration failed — wake recovery disabled.");
        }

        SGReachabilityMonitor *reachability = [[SGReachabilityMonitor alloc] initWithChangeHandler:^(BOOL isReachable, BOOL isWWAN) {
            if (isReachable) {
                [daemon systemNetworkReachabilityDidChangeWithWWANStatus:isWWAN];
            } else {
                [daemon systemNetworkDidDrop];
            }
        }];

        /**
         * Always start the daemon before wiring reachability.
         *
         * start initializes the Mach IPC layer and reconciles tokens.  If we
         * skip it when offline, apps can never request tokens — even after
         * WiFi reconnects — because the IPC server was never launched.
         *
         * The FSM handles the no-network case on its own: the reachability
         * callback fires SGEventNetworkDown → SGStateIdleNoNetwork → retries
         * when WiFi returns.  Starting before wiring reachability also ensures
         * the FSM is fully initialized before the first callback arrives.
         */
        [daemon start];
        [reachability startMonitoringSystemNetworkChanges];

        CFRunLoopRun();

        SGLOGI(Skyglow, "SGDaemon shutting down...");
        [daemon requestGracefulDisconnect];
        [reachability stopMonitoringSystemNetworkChanges];

        /* Detach + stop channels before -release on the daemon so in-flight
         * handlers complete with SGCERR_UNREACHABLE first. */
        [daemon attachControlChannel:nil];
        [daemon attachSpringBoardClient:nil];
        [springBoardClient stop];
        [springBoardClient release];
        [controlChannel stop];
        [controlChannel release];

        SGStatusServer_Shutdown();
        [[SGDatabaseManager sharedManager] closeDatabase];

        if (_sgPowerNotifier != MACH_PORT_NULL) {
            IODeregisterForSystemPower(&_sgPowerNotifier);
            IOServiceClose(_sgPowerRootPort);
            IONotificationPortDestroy(_sgPowerNotifyPort);
        }
        dispatch_source_cancel(sigtermSource);
        dispatch_release(sigtermSource);

        [reachability release];
        [daemon release];
        
        unlink([SGPath(@"/var/run/skyglow_daemon.pid") UTF8String]);
        flock(pid_fd, LOCK_UN);
        close(pid_fd);

        SGLog_Flush();
        SGLog_CloseFile();
    }
    return 0;
}