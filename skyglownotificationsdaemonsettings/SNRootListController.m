#include "skyglownotificationsdaemonsettings/SNRegisterAccount.h"
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "SNRootListController.h"
#import "SNGuideViewController.h"
#import "SNLogViewController.h"

#define kBundlePath @"/Library/PreferenceBundles/SkyglowNotificationsDaemonSettings.bundle"

@implementation SNRootListController

- (NSArray *)specifiers {
	if (!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
	}

	return _specifiers;
}

- (void)reloadDaemon {
    NSLog(@"[Sndrestart] Invoking the binary to restart the daemon");
    
    pid_t pid;
    char *args[] = {"/Library/PreferenceBundles/SkyglowNotificationsDaemonSettings.bundle/sndrestart", NULL};
    int status;
    
    // Spawn the process
    status = posix_spawn(&pid, args[0], NULL, NULL, args, environ);
    
    if (status == 0) {
        NSLog(@"[Sndrestart] Successfully spawned the process.");
        
        // Wait for the spawned process to finish, if necessary
        if (waitpid(pid, &status, 0) == -1) {
            NSLog(@"[Sndrestart] Error waiting for the process to finish.");
        } else {
            NSLog(@"[Sndrestart] Process finished.");
        }
    } else {
        NSLog(@"[Sndrestart] Failed to spawn the process.");
    }
}

- (void)showGuide {
    GuideViewController *guideVC = [[GuideViewController alloc] init];
    [self.navigationController pushViewController:guideVC animated:YES];
}

- (void)registerDevice {
    UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"Registering Device"
                                                    message:@"\n" // Increase the number of line breaks for additional spacing
                                                   delegate:nil
                                          cancelButtonTitle:nil
                                          otherButtonTitles:nil];
    UIActivityIndicatorView *activityView = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhiteLarge];

    // Show the alert first to get its dimensions
    [alert show];

    // Delayed adjustment to attempt to accommodate the alert's dynamic layout
    double delayInSeconds = 0.1;
    dispatch_time_t popTime = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delayInSeconds * NSEC_PER_SEC));
    dispatch_after(popTime, dispatch_get_main_queue(), ^(void){
        // Adjust spinner's frame directly to move it lower and possibly make the alert look "thinner"
        CGRect alertBounds = alert.bounds;
        CGPoint center = CGPointMake(CGRectGetMidX(alertBounds), CGRectGetMidY(alertBounds) + 20); // Adjust the Y offset as needed
        activityView.center = center;
        [alert addSubview:activityView];
        [activityView startAnimating];
    });

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Generate the keys
        NSString *serverAddress = [self getServerAddressFromPreferences];
        NSLog(@"[Skyglow Notifications] Registering with server %@", serverAddress);
        NSString *result = RegisterAccount(serverAddress);
        NSLog(@"[Skyglow Notifications] Registering with server finsished with %@. (null means sucess)", result);

        dispatch_async(dispatch_get_main_queue(), ^{
            // Dismiss the alert
            [alert dismissWithClickedButtonIndex:0 animated:YES];

            if (result) {
                [[[UIAlertView alloc] initWithTitle:@"Failed to Register Device!"
                                                    message:[NSString stringWithFormat:@"An error has occured while trying to register your device. (%@)", result]
                                                   delegate:nil
                                          cancelButtonTitle:@"Okay"
                                          otherButtonTitles:nil] show];
            }
        });
    });
}

- (NSString *)getServerAddressFromPreferences {
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    
    NSString *serverAddress = [prefs objectForKey:@"notificationServerAddress"];
    
    // Return default or user-specified address
    if (serverAddress.length > 0) {
        return serverAddress;
    } else {
        return @""; // Fallback to default if not set
    }
}


- (void)enabledToggled:(id)value specifier:(id)specifier {
    NSLog(@"[Skyglow Notifications] Toggle changed to %@, saving and reloading daemon", value);
    
    
    // [[[UIAlertView alloc] initWithTitle:@"Device is not registered yet!"
    //                                                 message:@"In order to enable Skyglow Notifications, you must first register. Enter the address of the server you want to register to, then press \"Register Device with Server\". The rest should be done automatically."
    //                                                delegate:nil
    //                                       cancelButtonTitle:@"Okay"
    //                                       otherButtonTitles:nil] show];

    // Save the value to preferences
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
    NSMutableDictionary *prefs;
    
    if ([[NSFileManager defaultManager] fileExistsAtPath:plistPath]) {
        prefs = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    } else {
        prefs = [NSMutableDictionary dictionary];
    }
    
    [prefs setObject:value forKey:@"enabled"];
    [prefs writeToFile:plistPath atomically:YES];
    
    // Now reload the daemon
    [self reloadDaemon];
}

@end
