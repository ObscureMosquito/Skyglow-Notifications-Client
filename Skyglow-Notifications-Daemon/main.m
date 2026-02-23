#import <Foundation/Foundation.h>
#import "SGDaemon.h"
#import "SGReachabilityMonitor.h"
#import "SGServerLocator.h"
#import "SGConfiguration.h"
#import "SGDatabaseManager.h"
#import "SGMachServer.h"
#import "SGStatusServer.h"
#import "SGProtocolHandler.h"
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>

static void SG_ConfigurationReloadCallback(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    SGDaemon *daemon = (__bridge SGDaemon *)observer;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool { [daemon handleConfigurationReloadRequest]; }
    });
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        signal(SIGPIPE, SIG_IGN);

        // Check if we are enabled
        NSString *prefsPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
        NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:prefsPath];
        BOOL isEnabled = (prefs && [prefs objectForKey:@"enabled"]) ? [[prefs objectForKey:@"enabled"] boolValue] : NO;
        
        if (!isEnabled) {
            NSLog(@"[Skyglow] Daemon is disabled. Exiting.");
            exit(EXIT_SUCCESS);
        }
        
        // Single Instance Assurance via PID Lock
        int pid_fd = open("/var/run/skyglow_daemon.pid", O_RDWR | O_CREAT, 0666);
        if (pid_fd < 0) {
            NSLog(@"[Skyglow] FATAL: Could not create or open PID file.");
            exit(EXIT_FAILURE);
        }
        
        fchmod(pid_fd, 0666);
        
        if (flock(pid_fd, LOCK_EX | LOCK_NB) != 0) {
            NSLog(@"[Skyglow] FATAL: Another instance of Skyglow Notifications Daemon is already running! Aborting.");
            close(pid_fd);
            exit(EXIT_FAILURE);
        }

        ftruncate(pid_fd, 0);
        dprintf(pid_fd, "%d\n", getpid());
        
        NSLog(@"Speedy Execution Is The Mother Of Good Fortune");
        NSLog(@"[Skyglow] Daemon starting");

        // Initialize Singletons
        SGConfiguration *config = [SGConfiguration sharedConfiguration];

        NSString *profilePath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
        NSDictionary *profile = [NSDictionary dictionaryWithContentsOfFile:profilePath];
        id addrObj = profile[@"server_address"];
        if ([addrObj isKindOfClass:[NSString class]]) {
            [config setServerAddress:addrObj];  
        }

        // Start Core Services
        SGStatusServer_Start("/var/run/skyglow_status.sock", (int64_t)time(NULL));
        
        SGMachServer *machServer = [[SGMachServer alloc] init];
        [machServer startMachBootstrapServices];

        SGDaemon *daemon = [[SGDaemon alloc] init];
        
        //  Setup Reachability Orchestration
        SGReachabilityMonitor *reachability = [[SGReachabilityMonitor alloc] initWithChangeHandler:^(BOOL isReachable, BOOL isWWAN) {
            if (isReachable) {
                [daemon systemNetworkReachabilityDidChangeWithWWANStatus:isWWAN];
            } else {
                SGP_AbortConnection();
                [daemon transitionToState:SGStateIdleNoNetwork];
            }
        }];

        // Setup Darwin Observers
        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), 
                                        (__bridge void *)daemon, 
                                        SG_ConfigurationReloadCallback, 
                                        CFSTR(kSGConfigurationDidUpdateNotification), 
                                        NULL, 
                                        CFNotificationSuspensionBehaviorDeliverImmediately);

        // Start Monitoring and Enter RunLoop
        [reachability startMonitoringSystemNetworkChanges];
        
        if (reachability.isReachable) {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                [daemon runPrimaryConnectionLoop];
            });
        }

        CFRunLoopRun();

        // Graceful Teardown
        NSLog(@"[Skyglow] SGDaemon shutting down...");
        [daemon requestGracefulDisconnect];
        [reachability stopMonitoringSystemNetworkChanges];
        SGStatusServer_Shutdown();
        [[SGDatabaseManager sharedManager] closeDatabase];
        
        [machServer release];
        [reachability release];
        [daemon release];
        
        // Release PID lock
        unlink("/var/run/skyglow_daemon.pid");
        flock(pid_fd, LOCK_UN);
        close(pid_fd);
    }
    return 0;
}