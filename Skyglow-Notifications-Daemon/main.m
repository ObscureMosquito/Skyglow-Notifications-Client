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

static void SG_ConfigurationReloadCallback(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    SGDaemon *daemon = (__bridge SGDaemon *)observer;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool { [daemon handleConfigurationReloadRequest]; }
    });
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        signal(SIGPIPE, SIG_IGN);
        NSLog(@"Speedy Execution Is The Mother Of Good Fortune");
        NSLog(@"[Skyglow] Daemon starting");

        // 1. Initialize Singletons
        SGConfiguration *config = [SGConfiguration sharedConfiguration];

        // 2. Load Initial Profile
        NSString *profilePath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
        NSDictionary *profile = [NSDictionary dictionaryWithContentsOfFile:profilePath];
        id addrObj = profile[@"server_address"];
        if ([addrObj isKindOfClass:[NSString class]]) {
            [config setServerAddress:addrObj];
        }

        // 3. Start Core Services
        SGStatusServer_Start("/var/run/skyglow_status.sock", (int64_t)time(NULL));
        
        SGMachServer *machServer = [[SGMachServer alloc] init];
        [machServer startMachBootstrapServices];

        SGDaemon *daemon = [[SGDaemon alloc] init];
        
        // 4. Setup Reachability Orchestration
        SGReachabilityMonitor *reachability = [[SGReachabilityMonitor alloc] initWithChangeHandler:^(BOOL isReachable, BOOL isWWAN) {
            if (isReachable) {
                [daemon systemNetworkReachabilityDidChangeWithWWANStatus:isWWAN];
            } else {
                SGP_AbortConnection();
                [daemon transitionToState:SGStateIdleNoNetwork];
            }
        }];

        // 5. Setup Darwin Observers
        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), 
                                        (__bridge void *)daemon, 
                                        SG_ConfigurationReloadCallback, 
                                        CFSTR(kSGConfigurationDidUpdateNotification), 
                                        NULL, 
                                        CFNotificationSuspensionBehaviorDeliverImmediately);

        // 6. Start Monitoring and Enter RunLoop
        [reachability startMonitoringSystemNetworkChanges];
        
        if (reachability.isReachable) {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                [daemon runPrimaryConnectionLoop];
            });
        }

        CFRunLoopRun();

        // 7. Graceful Teardown
        NSLog(@"[Skyglow] SGDaemon shutting down...");
        [daemon requestGracefulDisconnect];
        [reachability stopMonitoringSystemNetworkChanges];
        SGStatusServer_Shutdown();
        [[SGDatabaseManager sharedManager] closeDatabase];
        
        [machServer release];
        [reachability release];
        [daemon release];
    }
    return 0;
}