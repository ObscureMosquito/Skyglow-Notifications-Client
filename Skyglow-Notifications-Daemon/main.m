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

        SGConfiguration *config = [SGConfiguration sharedConfiguration];

        BOOL isEnabled = config.isEnabled;
        
        if (!isEnabled) {
            NSLog(@"[Skyglow] Daemon is disabled. Exiting.");
            exit(EXIT_SUCCESS);
        }
        
        int pid_fd = open([SGPath(@"/var/run/skyglow_daemon.pid") UTF8String], O_RDWR | O_CREAT, 0666);
        if (pid_fd < 0) {
            NSLog(@"[Skyglow] FATAL: Could not create or open PID file.");
            exit(EXIT_FAILURE);
        }
        
        // DONT REMOVE THIS PLS
        /*dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            SGTokenManager *testManager = [[SGTokenManager alloc] init];
            NSError *error = nil;
            
            NSLog(@"[SGN] Testing manual token generation for com.skyglow.WindFall...");
            NSData *token = [testManager synchronizedTokenForBundleIdentifier:@"com.skyglow.WindFall" error:&error];
            
            if (token) {
                NSLog(@"[SGN] Success! Token generated and sent to server: %@", token);
            } else {
                NSLog(@"[SGN] Failed to generate token: %@", error);
            }
            
            [testManager release];
        });*/

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

        SGStatusServer_Start([SGPath(@"/var/run/skyglow_status.sock") UTF8String], (int64_t)time(NULL));
        
        SGMachServer *machServer = [[SGMachServer alloc] init];
        [machServer startMachBootstrapServices];

        SGDaemon *daemon = [[SGDaemon alloc] init];
        SGP_SetDelegate(daemon);
        
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

        [reachability startMonitoringSystemNetworkChanges];
        
        if (reachability.isReachable) {
            [daemon start]; 
        }

        CFRunLoopRun();

        NSLog(@"[Skyglow] SGDaemon shutting down...");
        [daemon requestGracefulDisconnect];
        [reachability stopMonitoringSystemNetworkChanges];
        SGStatusServer_Shutdown();
        [[SGDatabaseManager sharedManager] closeDatabase];
        
        [machServer release];
        [reachability release];
        [daemon release];
        
        unlink([SGPath(@"/var/run/skyglow_daemon.pid") UTF8String]);
        flock(pid_fd, LOCK_UN);
        close(pid_fd);
    }
    return 0;
}