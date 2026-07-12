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
    if (SGNRegistrationConsumePassThrough()) { %orig; return; }

    if (SGN_IsCascadeReEntry(bundleIdentifier)) {
        NSLog(@"[SGN] Suppressing deregister cascade for %@", bundleIdentifier);
        %orig;
        return;
    }

    if (SGNEffectiveAppIntent(bundleIdentifier)) {
        SGN_InstallTokenGuard();
        SGN_AsyncFetchAndDeliverToken(bundleIdentifier, nil, nil, 0, nil);
        %orig;
        return;
    }

    if (SGN_BundleRegisteredWithNativePush(bundleIdentifier)) {
        %orig;
        return;
    }

    SGNRegistrationPresentModernChoice(self, bundleIdentifier, resultBlock);
}
%end
%end

#pragma mark - Constructor

%ctor {
    SGNInstallCompatibilityShim();

    StartSpringBoardControlChannel();
    StartDaemonControlChannelClient();
    SGNScheduleInstalledApplicationReconciliation();

    if (SGN_IS_PRE_IOS_8) {
        %init(HookUninstall_Classic);
    } else {
        %init(HookUninstall_Modern);
    }

    if (SGN_IS_PRE_IOS_9) {
        %init(HookRegistration_Classic);
    } else {
        %init(HookRegistration_iOS9);
    }
}
