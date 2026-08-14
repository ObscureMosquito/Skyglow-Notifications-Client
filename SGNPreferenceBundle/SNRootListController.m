#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Preferences/PSSpecifier.h>
#import "SNRootListController.h"
#import "SNPaneHeader.h"
#import "SNDebugViewController.h"
#import "SNDataManager.h"
#import "SNChannelGateway.h"
#import "SNAlert.h"
#import "SNInterfaceColors.h"

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

    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    UIImage *iconImg = [UIImage imageWithContentsOfFile:[bundle pathForResource:@"icon-settings" ofType:@"png"]];
    UIImageView *iconView = [[[UIImageView alloc] initWithImage:iconImg] autorelease];
    iconView.contentMode = UIViewContentModeScaleAspectFit;
    iconView.frame       = CGRectMake(0, 0, 85.0f, 85.0f);

    self.table.tableHeaderView = SNPaneHeaderViewCreate(
        self.table.bounds.size.width, iconView,
        @"A push notification daemon, built from scratch.");
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

    if ([key isEqualToString:@"enabled"]) {
        PSSpecifier *specifierCopy = [specifier retain];
        [SNChannelGateway setEnabled:[value boolValue]
                          completion:^(BOOL ok, NSString *message) {
            if (!ok) {
                [self reloadSpecifier:specifierCopy animated:YES];
                [SNAlert presentMessage:message ?: @"The daemon did not accept the change."
                                  title:@"Could Not Update Skyglow"
                                   from:self];
            }
            [specifierCopy release];
        }];
        return;
    }
}

- (void)pushDebugView {
    SNDebugViewController *vc = [[SNDebugViewController alloc] init];
    [self.navigationController pushViewController:vc animated:YES];
    [vc release];
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
        _versionLabel.text = @"Version 3.0";
        _versionLabel.backgroundColor = [UIColor clearColor];
        _versionLabel.textColor = SNSecondaryLabelColor([UIColor colorWithRed:0.3f green:0.34f blue:0.42f alpha:1.0f]);
        _versionLabel.shadowColor = SNLegacyTextShadowColor([UIColor whiteColor]);
        _versionLabel.shadowOffset = CGSizeMake(0, 1);
        _versionLabel.font = [UIFont systemFontOfSize:12.5f];
        _versionLabel.textAlignment = NSTextAlignmentCenter;

        _creditsLabel = [[UILabel alloc] initWithFrame:CGRectZero];
        _creditsLabel.text = @"Tweak and protocol created by Requis - ObscureMosquito, improved and server created by Preloading.";
        _creditsLabel.backgroundColor = [UIColor clearColor];
        _creditsLabel.textColor = SNSecondaryLabelColor([UIColor colorWithRed:0.3f green:0.34f blue:0.42f alpha:1.0f]);
        _creditsLabel.shadowColor = SNLegacyTextShadowColor([UIColor whiteColor]);
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
