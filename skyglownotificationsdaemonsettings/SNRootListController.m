#include "skyglownotificationsdaemonsettings/SNRegisterAccount.h"
#import <Foundation/Foundation.h>
#include <Foundation/NSObjCRuntime.h>
#import <UIKit/UIKit.h>
#import <Preferences/PSSpecifier.h>
#import "SNRootListController.h"
#import "SNGuideViewController.h"
#import "SNLogViewController.h"
#import "SNAppToggleCell.h"
#import "SNAppListController.h"

@implementation SNRootListController

- (NSArray *)specifiers {
    if (!_specifiers) {
        _specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
    }
    return _specifiers;
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];

    NSString *key = [specifier propertyForKey:@"key"];
    id val = key ? prefs[key] : nil;

    if (val) return val;

    // Fallback to the default in Root.plist if file doesn't contain it
    id def = [specifier propertyForKey:@"default"];
    return def;
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier {
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
    NSString *key = [specifier propertyForKey:@"key"];
    if (!key) return;

    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    if (!prefs) prefs = [NSMutableDictionary dictionary];

    if (value) {
        prefs[key] = value;
    } else {
        [prefs removeObjectForKey:key];
    }

    // Write explicitly to the file you want both processes to share
    [prefs writeToFile:plistPath atomically:YES];

    // Optional: also keep CFPreferences in sync with the same domain (helps UI consistency)
    CFStringRef appID = CFSTR("com.skyglow.sndp");
    CFPreferencesSetAppValue((CFStringRef)key, (__bridge CFPropertyListRef)value, appID);
    CFPreferencesAppSynchronize(appID);

    [self reloadDaemon];
}

- (void)reloadDaemon {
    NSLog(@"[Sndrestart] Invoking sndrestart to restart the daemon");

    // Find sndrestart inside this bundle (works on rootful + rootless)
    NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:@"sndrestart" ofType:nil];
    if (!path) {
        NSLog(@"[Sndrestart] sndrestart not found in bundle");
        return;
    }

    pid_t pid = 0;
    const char *cpath = [path fileSystemRepresentation];
    char *const args[] = { (char *)cpath, NULL };

    int status = posix_spawn(&pid, cpath, NULL, NULL, args, environ);
    if (status != 0) {
        NSLog(@"[Sndrestart] posix_spawn failed: %d", status);
        return;
    }

    int wstatus = 0;
    if (waitpid(pid, &wstatus, 0) == -1) {
        NSLog(@"[Sndrestart] Error waiting for the process to finish.");
    } else {
        NSLog(@"[Sndrestart] Process finished.");
    }
}

- (void)showGuide {
    GuideViewController *guideVC = [[GuideViewController alloc] init];
    [self.navigationController pushViewController:guideVC animated:YES];
}

- (void)registerDevice {
    [self.view endEditing:YES];
    CFPreferencesAppSynchronize(CFSTR("com.skyglow.sndp"));

    __block id uiToken = nil;
    [self presentRegisteringUIWithCompletion:^(id token) {
        uiToken = token;
    }];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self reloadDaemon];

        NSString *dbPath = @"/var/mobile/Library/SkyglowNotifications/sqlite.db";
        NSFileManager *fileManager = [NSFileManager defaultManager];
        if ([fileManager fileExistsAtPath:dbPath]) {
            NSError *error = nil;
            [fileManager removeItemAtPath:dbPath error:&error];
            if (error != nil) NSLog(@"An error occured while deleting the DB! %@", error);
        }

        NSString *serverAddress = [self getServerAddressFromPreferences];
        NSLog(@"[Skyglow Notifications] Registering with server %@", serverAddress);
        NSString *result = RegisterAccount(serverAddress);
        NSLog(@"[Skyglow Notifications] Registering finished with %@. (null means success)", result);

        dispatch_async(dispatch_get_main_queue(), ^{
            [self dismissRegisteringUI:uiToken];

            if (result) {
                if ([UIAlertController class]) {
                    UIAlertController *ac =
                        [UIAlertController alertControllerWithTitle:@"Failed to Register Device!"
                                                            message:[NSString stringWithFormat:
                                                                     @"An error has occured while trying to register your device. (%@)",
                                                                     result]
                                                     preferredStyle:UIAlertControllerStyleAlert];
                    [ac addAction:[UIAlertAction actionWithTitle:@"Okay" style:UIAlertActionStyleDefault handler:nil]];
                    [self presentViewController:ac animated:YES completion:nil];
                } else {
                    [[[UIAlertView alloc] initWithTitle:@"Failed to Register Device!"
                                                message:[NSString stringWithFormat:
                                                         @"An error has occured while trying to register your device. (%@)",
                                                         result]
                                               delegate:nil
                                      cancelButtonTitle:@"Okay"
                                      otherButtonTitles:nil] show];
                }
            } else {
                [self reloadDaemon];
            }
        });
    });
}

- (void)presentRegisteringUIWithCompletion:(void (^)(id uiToken))completion {
    if ([UIAlertController class]) {
        UIAlertController *ac =
            [UIAlertController alertControllerWithTitle:@"Registering Device"
                                                message:@"\n"
                                         preferredStyle:UIAlertControllerStyleAlert];

        UIActivityIndicatorView *spinner =
            [[UIActivityIndicatorView alloc]
                initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhiteLarge];
        spinner.translatesAutoresizingMaskIntoConstraints = NO;
        [ac.view addSubview:spinner];

        [NSLayoutConstraint activateConstraints:@[
            [spinner.centerXAnchor constraintEqualToAnchor:ac.view.centerXAnchor],
            [spinner.centerYAnchor constraintEqualToAnchor:ac.view.centerYAnchor constant:15]
        ]];

        [spinner startAnimating];
        [self presentViewController:ac animated:YES completion:nil];

        if (completion) completion(ac);
    } else {
        // iOS 6 / 7
        UIAlertView *alert =
            [[UIAlertView alloc] initWithTitle:@"Registering Device"
                                       message:@"\n"
                                      delegate:nil
                             cancelButtonTitle:nil
                             otherButtonTitles:nil];

        UIActivityIndicatorView *spinner =
            [[UIActivityIndicatorView alloc]
                initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhiteLarge];

        [alert show];

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            CGRect b = alert.bounds;
            spinner.center = CGPointMake(CGRectGetMidX(b), CGRectGetMidY(b) + 20);
            [alert addSubview:spinner];
            [spinner startAnimating];
        });

        if (completion) completion(alert);
    }
}

- (void)dismissRegisteringUI:(id)uiToken {
    if (!uiToken) return;

    if ([uiToken isKindOfClass:[UIAlertController class]]) {
        [((UIAlertController *)uiToken) dismissViewControllerAnimated:YES completion:nil];
    } else {
        // UIAlertView
        UIAlertView *av = (UIAlertView *)uiToken;
        [av dismissWithClickedButtonIndex:0 animated:YES];
    }
}

- (NSString *)getServerAddressFromPreferences {
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];

    NSString *serverAddress = [prefs objectForKey:@"notificationServerAddress"];
    if (serverAddress.length > 0) {
        return serverAddress;
    }
    return @"";
}

@end
