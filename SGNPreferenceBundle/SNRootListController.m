#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Preferences/PSSpecifier.h>
#import "SNRootListController.h"
#import "SNServerInfoViewController.h"
#import "SNDebugViewController.h"
#import "SNCustomizationViewController.h"
#import "SNDataManager.h"
#import "SNChannelGateway.h"

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
    [backItem release];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self _installTableHeaderIfNeeded];
    [self reloadSpecifiers];
}

- (void)_installTableHeaderIfNeeded {
    if (self.table.tableHeaderView) return;

    CGFloat w = self.table.bounds.size.width;
    if (w < 10.0f) w = 320.0f;

    CGFloat iconSize  = 85.0f;
    CGFloat topPad    = 22.0f;
    CGFloat iconGap   = 10.0f;
    CGFloat titleGap  = 4.0f;
    CGFloat bodyGap   = 12.0f;
    CGFloat botPad    = 18.0f;
    CGFloat sideInset = 24.0f;

    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    UIImage *iconImg = [UIImage imageWithContentsOfFile:[bundle pathForResource:@"icon-settings" ofType:@"png"]];

    UIImageView *iconView = [[UIImageView alloc] initWithImage:iconImg];
    iconView.contentMode  = UIViewContentModeScaleAspectFit;
    iconView.frame        = CGRectMake((w - iconSize) / 2.0f, topPad, iconSize, iconSize);
    iconView.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleRightMargin;

    UILabel *titleLabel = [[UILabel alloc] init];
    titleLabel.text         = @"Skyglow Notifications";
    titleLabel.font         = [UIFont boldSystemFontOfSize:17.0f];
    titleLabel.textColor    = [UIColor colorWithRed:0.18f green:0.18f blue:0.18f alpha:1.0f];
    titleLabel.shadowColor  = [UIColor colorWithWhite:1.0f alpha:0.7f];
    titleLabel.shadowOffset = CGSizeMake(0, 1);
    titleLabel.textAlignment    = NSTextAlignmentCenter;
    titleLabel.backgroundColor  = [UIColor clearColor];
    titleLabel.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleRightMargin;
    [titleLabel sizeToFit];
    CGFloat titleY = topPad + iconSize + iconGap;
    titleLabel.frame = CGRectMake((w - titleLabel.frame.size.width) / 2.0f,
                                  titleY,
                                  titleLabel.frame.size.width,
                                  titleLabel.frame.size.height);

    UILabel *bodyLabel = [[UILabel alloc] init];
    bodyLabel.text          = @"A push notification daemon, built from scratch.";
    bodyLabel.font          = [UIFont systemFontOfSize:13.0f];
    bodyLabel.textColor     = [UIColor colorWithRed:0.38f green:0.38f blue:0.42f alpha:1.0f];
    bodyLabel.shadowColor   = [UIColor colorWithWhite:1.0f alpha:0.6f];
    bodyLabel.shadowOffset  = CGSizeMake(0, 1);
    bodyLabel.textAlignment    = NSTextAlignmentCenter;
    bodyLabel.backgroundColor  = [UIColor clearColor];
    bodyLabel.numberOfLines    = 0;
    bodyLabel.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleRightMargin;
    CGFloat bodyY = titleY + titleLabel.frame.size.height + titleGap;
    CGSize bodyFit = [bodyLabel sizeThatFits:CGSizeMake(w - sideInset * 2.0f, 999.0f)];
    bodyLabel.frame = CGRectMake((w - bodyFit.width) / 2.0f, bodyY, bodyFit.width, bodyFit.height);

    CGFloat totalH = bodyY + bodyFit.height + bodyGap + botPad;
    UIView *header = [[UIView alloc] initWithFrame:CGRectMake(0, 0, w, totalH)];
    header.backgroundColor  = [UIColor clearColor];
    header.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [header addSubview:iconView];
    [header addSubview:titleLabel];
    [header addSubview:bodyLabel];

    self.table.tableHeaderView = header;

    [iconView release];
    [titleLabel release];
    [bodyLabel release];
    [header release];
}

- (NSArray *)specifiers {
    if (!_specifiers) {
        _specifiers = [[self loadSpecifiersFromPlistName:@"Root" target:self] retain];
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
    
    [SNChannelGateway postReloadConfig];
}

- (void)pushDebugView {
    SNDebugViewController *vc = [[SNDebugViewController alloc] init];
    [self.navigationController pushViewController:vc animated:YES];
    [vc release];
}

- (void)pushCustomizationView {
    SNCustomizationViewController *vc = [[SNCustomizationViewController alloc] init];
    [self.navigationController pushViewController:vc animated:YES];
    [vc release];
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
    UILabel *_creditsLabel;
    UILabel *_versionLabel;
}

- (id)initWithSpecifier:(PSSpecifier *)specifier {
    self = [super initWithFrame:CGRectZero];
    if (self) {
        _versionLabel = [[UILabel alloc] initWithFrame:CGRectZero];
        _versionLabel.text = @"Version 1.0";
        _versionLabel.backgroundColor = [UIColor clearColor];
        _versionLabel.textColor = [UIColor colorWithRed:0.3f green:0.34f blue:0.42f alpha:1.0f];
        _versionLabel.shadowColor = [UIColor whiteColor];
        _versionLabel.shadowOffset = CGSizeMake(0, 1);
        _versionLabel.font = [UIFont systemFontOfSize:12.5f];
        _versionLabel.textAlignment = NSTextAlignmentCenter;

        _creditsLabel = [[UILabel alloc] initWithFrame:CGRectZero];
        _creditsLabel.text = @"Tweak and protocol created by Requis - ObscureMosquito, improved and server created by Preloading.";
        _creditsLabel.backgroundColor = [UIColor clearColor];
        _creditsLabel.textColor = [UIColor colorWithRed:0.3f green:0.34f blue:0.42f alpha:1.0f];
        _creditsLabel.shadowColor = [UIColor whiteColor];
        _creditsLabel.shadowOffset = CGSizeMake(0, 1);
        _creditsLabel.font = [UIFont systemFontOfSize:13.4f];
        _creditsLabel.textAlignment = NSTextAlignmentCenter;
        _creditsLabel.numberOfLines = 0;
        
        [self addSubview:_creditsLabel];
        [self addSubview:_versionLabel];
    }
    return self;
}

- (void)dealloc {
    [_versionLabel release];
    [_creditsLabel release];
    [_logoView release];
    [super dealloc];
}

- (CGFloat)preferredHeightForWidth:(CGFloat)width {
    CGFloat sideInset = 16.0f;
    CGSize creditsFit = [_creditsLabel sizeThatFits:CGSizeMake(width - sideInset * 2.0f, 999.0f)];
    return 8.0f + 20.0f + 6.0f + creditsFit.height + 25.0f;
}

- (void)layoutSubviews {
    [super layoutSubviews];

    CGRect bounds = self.bounds;

    CGFloat sideInset = 16.0f;
    CGFloat creditsW = bounds.size.width - sideInset * 2.0f;
    CGSize  creditsFit = [_creditsLabel sizeThatFits:CGSizeMake(creditsW, 999.0f)];

    _creditsLabel.frame = CGRectMake(sideInset, 0.0f, creditsW, creditsFit.height);
    _versionLabel.frame = CGRectMake(0, CGRectGetMaxY(_creditsLabel.frame) + 15.0f,
                                    bounds.size.width, 20.0f);
}
@end
