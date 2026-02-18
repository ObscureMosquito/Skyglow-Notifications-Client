#include "skyglownotificationsdaemonsettings/SNRegisterAccount.h"
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Preferences/PSSpecifier.h>
#import "SNRootListController.h"
#import "SNServerInfoViewController.h"

@implementation SNRootListController

- (NSBundle *)bundle {
    return [NSBundle bundleForClass:[self class]];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // iOS 6 Style Back Button
    UIBarButtonItem *backItem = [[UIBarButtonItem alloc] initWithTitle:@"Back"
                                                                 style:UIBarButtonItemStyleBordered
                                                                target:nil
                                                                action:nil];
    self.navigationItem.backBarButtonItem = backItem;
}

- (NSArray *)specifiers {
    if (!_specifiers) {
        _specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
    }
    return _specifiers;
}

// Pref reading/writing logic remains same as it uses standard NSDictionary/CFPreferences
- (id)readPreferenceValue:(PSSpecifier *)specifier {
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    NSString *key = [specifier propertyForKey:@"key"];
    id val = key ? prefs[key] : nil;
    return val ?: [specifier propertyForKey:@"default"];
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier {
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
    NSString *key = [specifier propertyForKey:@"key"];
    if (!key) return;
    
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath] ?: [NSMutableDictionary dictionary];
    if (value) prefs[key] = value;
    else [prefs removeObjectForKey:key];
    
    [prefs writeToFile:plistPath atomically:YES];
    
    CFStringRef appID = CFSTR("com.skyglow.sndp");
    CFPreferencesSetAppValue((__bridge CFStringRef)key, (__bridge CFPropertyListRef)value, appID);
    CFPreferencesAppSynchronize(appID);
    
    [self reloadDaemon];
}

- (void)reloadDaemon {
    NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:@"sndrestart" ofType:nil];
    if (!path) return;
    
    pid_t pid = 0;
    const char *cpath = [path fileSystemRepresentation];
    char *const args[] = { (char *)cpath, NULL };
    extern char **environ;
    
    if (posix_spawn(&pid, cpath, NULL, NULL, args, environ) == 0) {
        waitpid(pid, NULL, 0);
    }
}

- (void)navigateToInfo {
    SNServerInfoViewController *vc = [[SNServerInfoViewController alloc] init];
    [self.navigationController pushViewController:vc animated:YES];
}

- (void)registerDevice {
    [self.view endEditing:YES];
    
    __block UIAlertView *loadingAlert = nil;
    [self presentRegisteringUIWithCompletion:^(id token) {
        loadingAlert = (UIAlertView *)token;
    }];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self reloadDaemon];
        
        // Clean up DB
        NSFileManager *fileManager = [NSFileManager defaultManager];
        [fileManager removeItemAtPath:@"/var/mobile/Library/SkyglowNotifications/sqlite.db" error:nil];
        
        NSString *serverAddress = [self getServerAddressFromPreferences];
        NSString *result = RegisterAccount(serverAddress);
        
        dispatch_async(dispatch_get_main_queue(), ^{
            if (loadingAlert) [loadingAlert dismissWithClickedButtonIndex:0 animated:YES];
            
            if (result) {
                UIAlertView *errorAlert = [[UIAlertView alloc] initWithTitle:@"Failed to Register"
                                                                     message:[NSString stringWithFormat:@"Error: %@", result]
                                                                    delegate:nil
                                                           cancelButtonTitle:@"Okay"
                                                           otherButtonTitles:nil];
                [errorAlert show];
            } else {
                [self reloadDaemon];
            }
        });
    });
}

- (void)presentRegisteringUIWithCompletion:(void (^)(id uiToken))completion {
    UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"Registering Device"
                                                    message:@"\n"
                                                   delegate:nil
                                          cancelButtonTitle:nil
                                          otherButtonTitles:nil];
    
    UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhiteLarge];
    [alert show];
    
    // Classic iOS 6 subview injection
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        CGRect b = alert.bounds;
        spinner.center = CGPointMake(CGRectGetMidX(b), CGRectGetMidY(b) + 25);
        [alert addSubview:spinner];
        [spinner startAnimating];
    });
    
    if (completion) completion(alert);
}

- (void)dismissRegisteringUI:(id)uiToken {
    if ([uiToken isKindOfClass:[UIAlertView class]]) {
        [(UIAlertView *)uiToken dismissWithClickedButtonIndex:0 animated:YES];
    }
}

- (NSString *)getServerAddressFromPreferences {
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.skyglow.sndp.plist"];
    return [prefs objectForKey:@"notificationServerAddress"] ?: @"";
}

@end