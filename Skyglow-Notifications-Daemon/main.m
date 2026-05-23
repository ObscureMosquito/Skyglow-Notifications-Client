#import <Foundation/Foundation.h>
#import "SGDaemon.h"
#import "SGReachabilityMonitor.h"
#import "SGServerLocator.h"
#import "SGConfiguration.h"
#import "SGDatabaseManager.h"
#import "SGMachServer.h"
#import "SGStatusServer.h"
#import "SGProtocolHandler.h"
#import "SGTokenManager.h"
#import "SGLog.h"
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/IOMessage.h>

/**
 * Rotation threshold for /var/log/skyglow.log.  1 MB × 2 generations keeps
 * roughly 8–24 hours of typical traffic on disk without unbounded growth.
 * Bump if Debug/Trace logging becomes a routine diagnostic posture.
 */
#define SG_LOG_ROTATE_BYTES (1024u * 1024u)

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

static void SG_ConfigurationReloadCallback(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    SGDaemon *daemon = (__bridge SGDaemon *)observer;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool { [daemon handleConfigurationReloadRequest]; }
    });
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
        int64_t startTime = (int64_t)time(NULL);
        SGStatusServer_Start([SGPath(@"/var/run/skyglow_status.sock") UTF8String], startTime);

        if (!config.isEnabled) {
            SGLOGI(Skyglow, "Daemon is disabled. Broadcasting state and exiting.");
            SGStatusServer_Post(SGStateDisabled, 0, 0, NULL, "Daemon is disabled", 0);
            usleep(200000); /* 200ms — let any watchers read the state */
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

        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), 
                                        (__bridge void *)daemon, 
                                        SG_ConfigurationReloadCallback, 
                                        CFSTR(kSGConfigurationDidUpdateNotification), 
                                        NULL, 
                                        CFNotificationSuspensionBehaviorDeliverImmediately);

        /**
         * Always start the daemon before wiring reachability.
         *
         * start initializes the Mach bootstrap server and reconciles tokens.
         * If we skip it when offline, apps can never request tokens — even after
         * WiFi reconnects — because the Mach IPC server was never launched.
         *
         * The FSM handles the no-network case on its own: the reachability callback
         * fires SGEventNetworkDown → SGStateIdleNoNetwork → retries when WiFi returns.
         * Starting before wiring reachability also ensures the FSM is fully initialized
         * before the first callback arrives.
         */
        [daemon start];
        [reachability startMonitoringSystemNetworkChanges];

        CFRunLoopRun();

        SGLOGI(Skyglow, "SGDaemon shutting down...");
        [daemon requestGracefulDisconnect];
        [reachability stopMonitoringSystemNetworkChanges];

        /**
         * Remove the config-reload observer before releasing the daemon.
         * SG_ConfigurationReloadCallback dispatches [daemon handleConfigurationReloadRequest]
         * to the global queue. A Darwin notification delivered between CFRunLoopRun()
         * returning and [daemon release] below would dispatch a block that calls into
         * a being-torn-down object — no implicit retain in MRC.
         */
        CFNotificationCenterRemoveEveryObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            (__bridge void *)daemon);

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