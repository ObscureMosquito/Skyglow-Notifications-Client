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
    
    CFStringRef appID = CFSTR("com.skyglow.sndp");
    CFPreferencesSetAppValue((__bridge CFStringRef)key, (__bridge CFPropertyListRef)value, appID);
    CFPreferencesAppSynchronize(appID);
    
    CFNotificationCenterPostNotificationWithOptions(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFSTR("com.skyglow.sgn.reload_config"),
        NULL, NULL, kCFNotificationDeliverImmediately);
    
    [self reloadDaemon];
}

- (void)reloadDaemon {
    CFNotificationCenterPostNotificationWithOptions(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFSTR("com.skyglow.sgn.trigger_restart"),
        NULL, NULL, kCFNotificationDeliverImmediately);
}

- (void)pushDebugView {
    SNDebugViewController *vc = [[SNDebugViewController alloc] init];
    [self.navigationController pushViewController:vc animated:YES];
}

- (NSString *)getServerAddressFromPreferences {
    return [[SNDataManager shared] serverAddressInput];
}

@end

@interface SNFooterView : UIView
- (id)initWithSpecifier:(PSSpecifier *)specifier;
- (CGFloat)preferredHeightForWidth:(CGFloat)width;
@end

@implementation SNFooterView {
    UIImageView *_logoView;
    UILabel *_versionLabel;
}

- (id)initWithSpecifier:(PSSpecifier *)specifier {
    self = [super initWithFrame:CGRectZero];
    if (self) {
        NSBundle *bundle = [NSBundle bundleForClass:[self class]];
        UIImage *image = [UIImage imageWithContentsOfFile:[bundle pathForResource:@"icon-settings" ofType:@"png"]];
        
        _logoView = [[UIImageView alloc] initWithImage:image];
        _logoView.contentMode = UIViewContentModeScaleAspectFit;
        [self addSubview:_logoView];
        
        _versionLabel = [[UILabel alloc] initWithFrame:CGRectZero];
        _versionLabel.text = @"Version 1.0";
        _versionLabel.backgroundColor = [UIColor clearColor];
        _versionLabel.textColor = [UIColor colorWithRed:0.3f green:0.34f blue:0.42f alpha:1.0f];
        _versionLabel.shadowColor = [UIColor whiteColor];
        _versionLabel.shadowOffset = CGSizeMake(0, 1);
        _versionLabel.font = [UIFont systemFontOfSize:13.0f];
        _versionLabel.textAlignment = NSTextAlignmentCenter;
        
        [self addSubview:_versionLabel];
    }
    return self;
}

- (CGFloat)preferredHeightForWidth:(CGFloat)width {
    return 135.0f; 
}

- (void)layoutSubviews {
    [super layoutSubviews];
    
    CGRect bounds = self.bounds;
    
    CGFloat imageSize = 75.0f;
    _logoView.frame = CGRectMake((bounds.size.width - imageSize) / 2.0, 10.0, imageSize, imageSize);
    
    _versionLabel.frame = CGRectMake(0, CGRectGetMaxY(_logoView.frame) + 5.0, bounds.size.width, 20.0);
}
@end