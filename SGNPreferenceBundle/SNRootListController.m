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
    
    // Tell running daemon to re-read config (handles disable while connected)
    CFNotificationCenterPostNotificationWithOptions(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFSTR("com.skyglow.snd.reload_config"),
        NULL, NULL, kCFNotificationDeliverImmediately);
    
    // Also restart daemon via launchctl (handles enable when daemon wasn't running)
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

- (NSString *)getServerAddressFromPreferences {
    return [[SNDataManager shared] serverAddressInput];
}

@end