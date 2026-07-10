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
#import "SGControlPayloadCodec.h"
#import "SGControlCommandRouter.h"
#import "SGLog.h"
#import "SGMigration.h"
#import "SGPlatform.h"
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
        if (getuid() != 0 || geteuid() != 0) {
            setgid(0);
            setuid(0);
        }
        if (geteuid() != 0) {
            fprintf(stderr, "code=%s result=failed reason=privilege_elevation\n",
                    SGND_DAEMON_PRIVILEGE_FAILED);
            exit(EXIT_FAILURE);
        }

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

        SGControlChannel *platformChannel = nil;
#if !TARGET_OS_OSX
        platformChannel =
            [[SGControlChannel clientForServiceName:SKYGLOW_CONTROL_SERVICE_SPRINGBOARD] retain];
        __unsafe_unretained SGDaemon *daemonRef = daemon;
        [platformChannel setConnectionHandler:^(BOOL connected) {
            if (connected) [daemonRef kickLocalDeliveryDrain];
        }];
        [platformChannel start];
#endif
        SGPlatform *platform = [[SGPlatform alloc] initWithControlChannel:platformChannel];
        [daemon attachPlatform:platform];

        SGControlCommandRouter *router =
            [[SGControlCommandRouter alloc] initWithDaemon:daemon platform:platform];
        [router attachToChannel:controlChannel];

        if (![controlChannel start]) {
            SGLOGE(Skyglow, "code=%s service=%s result=failed", SGND_DAEMON_CONTROL_START_FAILED, SKYGLOW_CONTROL_SERVICE_DAEMON);
        } else {
            [daemon attachControlChannel:controlChannel];
        }

        [daemon.stateStore drainDurableEventInbox];
        [daemon start];

        CFRunLoopRun();

        SGLOGI(Skyglow, "code=%s pid=%d result=stopping", SGND_DAEMON_SHUTTING_DOWN, (int)getpid());
        [daemon requestGracefulDisconnect];

        [daemon attachControlChannel:nil];
        [daemon attachPlatform:nil];
#if !TARGET_OS_OSX
        [platformChannel stop];
        [platformChannel release];
#endif
        [controlChannel stop];
        [controlChannel release];
        [router release];
        [platform release];

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
