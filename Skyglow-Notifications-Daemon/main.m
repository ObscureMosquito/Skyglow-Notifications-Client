#import <Foundation/Foundation.h>
#import "NotificationDaemon.h"
#import "NetworkMonitor.h"
#import "ServerLocationFinder.h"
#import "Globals.h"
#import "DBManager.h"
#import "LocalIPC.h"
#import "StatusServer.h"

#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static void configReloadCallback(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    NotificationDaemon *daemon = (__bridge NotificationDaemon *)observer;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool { [daemon handleConfigReload]; }
    });
}

static void idleUntilConfigReload(NotificationDaemon *daemon) {
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), (__bridge void *)daemon, configReloadCallback, CFSTR(kDaemonReloadConfig), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    CFRunLoopRun();
    CFNotificationCenterRemoveObserver(CFNotificationCenterGetDarwinNotifyCenter(), (__bridge void *)daemon, CFSTR(kDaemonReloadConfig), NULL);
}

#define SGN_PID_FILE "/var/run/skyglow_snd.pid"

static void writePidFile(void) {
    int fd = open(SGN_PID_FILE, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd >= 0) {
        char buf[32]; snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
        write(fd, buf, strlen(buf)); close(fd);
    }
}

static void removePidFile(void) { unlink(SGN_PID_FILE); }

static int enforceSingleInstance(void) {
    int fd = open(SGN_PID_FILE, O_WRONLY|O_CREAT|O_EXCL, 0644);
    if (fd >= 0) {
        char buf[32]; snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
        write(fd, buf, strlen(buf)); close(fd); return 0;
    }
    if (errno != EEXIST) return 0; 

    FILE *f = fopen(SGN_PID_FILE, "r");
    pid_t oldPid = 0;
    if (f) { fscanf(f, "%d", &oldPid); fclose(f); }

    if (oldPid > 0 && kill(oldPid, 0) == 0) {
        NSLog(@"[Main] FATAL: daemon already running as PID %d", oldPid);
        return 1;
    }
    unlink(SGN_PID_FILE); writePidFile(); return 0;
}

static BOOL isValidIPAddress(NSString *ip) {
    if (!ip) return NO;
    struct sockaddr_in sa;
    return inet_pton(AF_INET, [ip UTF8String], &sa.sin_addr) == 1;
}

static BOOL isValidPort(NSString *port) {
    if (!port || [port length] == 0) return NO;
    NSCharacterSet *nonDigits = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
    if ([port rangeOfCharacterFromSet:nonDigits].location != NSNotFound) return NO;
    int p = [port intValue];
    return (p > 0 && p <= 65535);
}

int main(void) {
    @autoreleasepool {
        signal(SIGPIPE, SIG_IGN);

        if (enforceSingleInstance() != 0) return 1;

        int64_t startTime = (int64_t)time(NULL);
        if (StatusServer_start(SS_SOCKET_PATH, startTime) != 0) {
            NSLog(@"[Main] StatusServer failed to start");
        }

        NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
        NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];
        if (!prefs) {
            StatusServer_post(SGStateError, 0, 0, NULL);
            StatusServer_shutdown();
            return -1;
        }

        NotificationDaemon *daemon = [[NotificationDaemon alloc] init];

        if (![[prefs objectForKey:@"enabled"] boolValue]) {
            StatusServer_post(SGStateDisabled, 0, 0, NULL);
            idleUntilConfigReload(daemon);
            StatusServer_shutdown();
            [daemon release];
            return 0;
        }

        NSString *profilePath = @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist";
        NSDictionary *profile = [NSDictionary dictionaryWithContentsOfFile:profilePath];
        NSString *serverAddr  = profile[@"server_address"];

        if (![serverAddr isKindOfClass:[NSString class]] || [serverAddr length] == 0) {
            StatusServer_post(SGStateIdleUnregistered, 0, 0, NULL);
            idleUntilConfigReload(daemon);
            StatusServer_shutdown();
            [daemon release];
            return 0;
        }

        SetServerAddress(serverAddr);

        db = [DBManager sharedStorage];
        if (!db) {
            StatusServer_post(SGStateError, 0, 0, NULL);
            StatusServer_shutdown();
            SetServerAddress(nil);
            [daemon release];
            return -1;
        }

        StatusServer_post(SGStateResolvingDNS, 0, 0, NULL);

        NSDictionary *txtRecords = nil;
        for (int attempt = 1; attempt <= DNS_RETRY_COUNT; attempt++) {
            txtRecords = [ServerLocationFinder resolveServerLocation:serverAddr];
            if (txtRecords) break;
            if (attempt < DNS_RETRY_COUNT) sleep(DNS_RETRY_DELAY_SEC);
        }

        if (!txtRecords) {
            StatusServer_post(SGStateIdleDNSFailed, 0, 0, NULL);
            idleUntilConfigReload(daemon);
            StatusServer_shutdown();
            SetServerAddress(nil);
            db = nil; 
            [daemon release];
            return 0;
        }

        NSString *ip   = txtRecords[@"tcp_addr"];
        NSString *port = txtRecords[@"tcp_port"];

        if (!isValidIPAddress(ip) || !isValidPort(port)) {
            StatusServer_post(SGStateErrorBadConfig, 0, 0, NULL);
            StatusServer_shutdown();
            SetServerAddress(nil);
            db = nil;
            [daemon release];
            return -1;
        }

        SetServerIPString(ip);
        SetServerPortString(port);

        LocalIPC *localIpc = [[LocalIPC alloc] init];
        [localIpc startMachServer];

        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), (__bridge void *)daemon, configReloadCallback, CFSTR(kDaemonReloadConfig), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);

        NetworkMonitor *netMonitor = [[NetworkMonitor alloc] initWithCallback:^(BOOL isReachable, BOOL isWWAN) {
            if (isReachable) {
                [daemon networkBecameReachable:isWWAN]; 
            } else {
                [daemon transitionToState:SGStateIdleNoNetwork];
            }
        }];
        
        [netMonitor startMonitoring];
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 2.0, false);
        
        if (netMonitor.isReachable) {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                [daemon connectionLoop];
            });
        } else {
            StatusServer_post(SGStateIdleNoNetwork, 0, 0, [ip UTF8String]);
        }

        CFRunLoopRun();

        [daemon requestDisconnect];
        CFNotificationCenterRemoveObserver(CFNotificationCenterGetDarwinNotifyCenter(), (__bridge void *)daemon, CFSTR(kDaemonReloadConfig), NULL);

        [netMonitor stopMonitoring];
        [netMonitor release];

        StatusServer_shutdown();
        SetServerAddress(nil);
        SetServerIPString(nil);
        SetServerPortString(nil);
        [db release]; db = nil;
        [localIpc release];
        [daemon release];
    }

    removePidFile();
    return 0;
}