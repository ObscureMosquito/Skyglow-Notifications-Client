#import <Foundation/Foundation.h>
#import "SGNPrivateAPI.h"
#import "SGNAppIntent.h"
#import "SGNDaemonBridge.h"
#import "SGNNativePush.h"
#import "SGSharedConstants.h"
#import "SGCompatibilityShim.h"

#pragma mark - Uninstall Detection

%group HookUninstall_Classic
%hook SBApplicationUninstallationOperation
- (void)main {
    NSString *bundleId = nil;
    if ([(id)self respondsToSelector:@selector(bundleIdentifier)]) {
        bundleId = [(id)self performSelector:@selector(bundleIdentifier)];
    } else {
        @try { bundleId = [(id)self valueForKey:@"_bundleIdentifier"]; }
        @catch (NSException *e) { bundleId = nil; }
    }
    if (bundleId.length) {
        SGNSendDeleteAppCommand(bundleId);
    }
    %orig;
}
%end
%end

%group HookUninstall_Modern
%hook SBApplicationController
- (void)uninstallApplication:(id)application {
    NSString *bundleId = nil;
    if ([application respondsToSelector:@selector(bundleIdentifier)]) {
        bundleId = [application performSelector:@selector(bundleIdentifier)];
    }
    if (bundleId.length) {
        SGNSendDeleteAppCommand(bundleId);
    }
    %orig;
}
%end
%end

#pragma mark - Push Registration

static BOOL SGNModernRegistrationShouldPresentChoice(NSString *bundleIdentifier) {
    if (SGNRegistrationConsumePassThrough()) return NO;

    if (SGN_IsCascadeReEntry(bundleIdentifier)) {
        NSLog(@"[SGN] Suppressing deregister cascade for %@", bundleIdentifier);
        return NO;
    }

    if (SGNEffectiveAppIntent(bundleIdentifier)) {
        SGN_InstallTokenGuard();
        SGN_AsyncFetchAndDeliverToken(bundleIdentifier, nil, nil, 0, nil);
        return NO;
    }

    if (SGN_BundleRegisteredWithNativePush(bundleIdentifier)) return NO;

    return YES;
}

%group HookRegistration_Classic
%hook SBRemoteNotificationServer
- (int)registerApplication:(id)application forEnvironment:(id)environment withTypes:(int)notificationTypes {
    if (SGNRegistrationConsumePassThrough()) return %orig;

    NSString *bundleId = [application bundleIdentifier];

    if (SGN_IsCascadeReEntry(bundleId)) {
        NSLog(@"[SGN] Suppressing deregister cascade for %@", bundleId);
        return 0;
    }

    if (SGNEffectiveAppIntent(bundleId)) {
        SGN_InstallTokenGuard();
        SGN_AsyncFetchAndDeliverToken(bundleId, application, environment,
                                      notificationTypes, nil);
        return 1;
    }

    if (SGN_BundleRegisteredWithNativePush(bundleId)) {
        return %orig;
    }

    SGNRegistrationPresentClassicChoice(self, application, environment, bundleId, notificationTypes);
    return 0;
}
%end
%end

%group HookRegistration_iOS9
%hook UNNotificationRegistrarConnectionListener
- (void)requestTokenForRemoteNotificationsForBundleIdentifier:(NSString *)bundleIdentifier withResult:(id)resultBlock {
    if (!SGNModernRegistrationShouldPresentChoice(bundleIdentifier)) {
        %orig;
        return;
    }
    SGNRegistrationPresentModernChoice(self, bundleIdentifier, resultBlock,
                                       _cmd);
}
%end
%end

%group HookRegistration_iOS10
%hook UNSUserNotificationServerConnectionListener
- (void)requestTokenForRemoteNotificationsForBundleIdentifier:
            (NSString *)bundleIdentifier
                                      withCompletionHandler:(id)resultBlock {
    if (!SGNModernRegistrationShouldPresentChoice(bundleIdentifier)) {
        %orig;
        return;
    }
    SGNRegistrationPresentModernChoice(self, bundleIdentifier, resultBlock,
                                       _cmd);
}
%end
%end

#pragma mark - Constructor

%ctor {
    SGNInstallCompatibilityShim();

    StartSpringBoardControlChannel();
    StartDaemonControlChannelClient();
    SGNScheduleInstalledApplicationReconciliation();

    Class appController = NSClassFromString(@"SBApplicationController");
    if ([appController instancesRespondToSelector:@selector(uninstallApplication:)]) {
        %init(HookUninstall_Modern);
    } else {
        %init(HookUninstall_Classic);
    }

    if (NSClassFromString(@"UNSUserNotificationServerConnectionListener")) {
        %init(HookRegistration_iOS10);
    } else if (NSClassFromString(@"UNNotificationRegistrarConnectionListener")) {
        %init(HookRegistration_iOS9);
    } else {
        %init(HookRegistration_Classic);
    }
}
