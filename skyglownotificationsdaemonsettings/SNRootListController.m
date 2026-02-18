#include "skyglownotificationsdaemonsettings/SNRegisterAccount.h"
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Preferences/PSSpecifier.h>
#import "SNRootListController.h"
#import "SNServerInfoViewController.h"
#import "SNDebugViewController.h"
#import "SNDataManager.h"

@implementation SNRootListController

- (NSBundle *)bundle {
    return [NSBundle bundleForClass:[self class]];
}

- (void)viewDidLoad {
    [super viewDidLoad];
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

- (id)readPreferenceValue:(PSSpecifier *)specifier {
    NSString *key = [specifier propertyForKey:@"key"];
    if (!key) return [specifier propertyForKey:@"default"];
    
    NSDictionary *prefs = [[SNDataManager shared] mainPrefs];
    id val = [prefs objectForKey:key];
    return val ?: [specifier propertyForKey:@"default"];
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier {
    NSString *key = [specifier propertyForKey:@"key"];
    if (!key) return;
    
    [[SNDataManager shared] setMainPrefValue:value forKey:key];
    
    // Also sync via CFPreferences for backward compat
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

- (void)pushDebugView {
    SNDebugViewController *vc = [[SNDebugViewController alloc] init];
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
        [[NSFileManager defaultManager]
         removeItemAtPath:@"/var/mobile/Library/SkyglowNotifications/sqlite.db" error:nil];
        
        NSString *serverAddress = [[SNDataManager shared] serverAddressInput];
        NSString *result = RegisterAccount(serverAddress);
        
        dispatch_async(dispatch_get_main_queue(), ^{
            if (loadingAlert) [loadingAlert dismissWithClickedButtonIndex:0 animated:YES];
            
            if (result) {
                [[[UIAlertView alloc] initWithTitle:@"Failed to Register"
                                            message:[NSString stringWithFormat:@"Error: %@", result]
                                           delegate:nil
                                  cancelButtonTitle:@"Okay"
                                  otherButtonTitles:nil] show];
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
    UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc]
                                        initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhiteLarge];
    [alert show];
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
                       spinner.center = CGPointMake(CGRectGetMidX(alert.bounds), CGRectGetMidY(alert.bounds) + 25);
                       [alert addSubview:spinner];
                       [spinner startAnimating];
                   });
    
    if (completion) completion(alert);
}

- (NSString *)getServerAddressFromPreferences {
    return [[SNDataManager shared] serverAddressInput];
}

@end