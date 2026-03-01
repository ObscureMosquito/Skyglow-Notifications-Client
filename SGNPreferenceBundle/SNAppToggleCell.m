#import "SNAppToggleCell.h"
#import "SNDataManager.h"
#import <Preferences/PSSpecifier.h>
#import <Preferences/PSTableCell.h>
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>

@interface UIView (CenterY)
@property (nonatomic) CGFloat centerY;
@end

@implementation UIView (CenterY)
- (CGFloat)centerY { return self.center.y; }
- (void)setCenterY:(CGFloat)centerY {
    CGPoint c = self.center;
    c.y = centerY;
    self.center = c;
}
@end

@interface AppInfoHelper : NSObject
- (UIImage *)getIconForBundleId:(NSString *)bundleId;
- (NSString *)getAppNameForBundleId:(NSString *)bundleId;
@end

@implementation AppInfoHelper

- (NSDictionary *)mobileInstallationPlist {
    static NSDictionary *cached = nil;
    if (!cached) {
        cached = [NSDictionary dictionaryWithContentsOfFile:
                  @"/var/mobile/Library/Caches/com.apple.mobile.installation.plist"];
    }
    return cached;
}

- (NSDictionary *)entryForBundleId:(NSString *)bundleId {
    NSDictionary *info = [self mobileInstallationPlist];
    NSDictionary *entry = info[@"User"][bundleId];
    if (!entry) entry = info[@"System"][bundleId];
    return entry;
}

- (NSString *)getAppNameForBundleId:(NSString *)bundleId {
    NSDictionary *entry = [self entryForBundleId:bundleId];
    if (!entry) return nil;
    return entry[@"CFBundleDisplayName"] ?: entry[@"CFBundleName"];
}

- (UIImage *)getIconForBundleId:(NSString *)bundleId {
    NSDictionary *entry = [self entryForBundleId:bundleId];
    NSString *bundlePath = entry[@"Path"];
    if (!bundlePath) return nil;
    
    NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:
                               [bundlePath stringByAppendingPathComponent:@"Info.plist"]];
    if (!infoPlist) return nil;
    
    NSMutableArray *loaded = [NSMutableArray array];
    
    NSDictionary *iconsDict = infoPlist[@"CFBundleIcons"];
    if (iconsDict) {
        NSArray *files = iconsDict[@"CFBundlePrimaryIcon"][@"CFBundleIconFiles"];
        for (NSString *name in files) {
            NSString *path = [bundlePath stringByAppendingPathComponent:name];
            if ([path pathExtension].length == 0) path = [path stringByAppendingPathExtension:@"png"];
            UIImage *img = [UIImage imageWithContentsOfFile:path];
            if (img) [loaded addObject:img];
        }
    } else {
        NSString *name = infoPlist[@"CFBundleIconFile"];
        if (name) {
            NSString *path = [bundlePath stringByAppendingPathComponent:name];
            if ([path pathExtension].length == 0) path = [path stringByAppendingPathExtension:@"png"];
            UIImage *img = [UIImage imageWithContentsOfFile:path];
            if (img) [loaded addObject:img];
        }
    }
    
    UIImage *best = nil;
    CGFloat maxArea = 0;
    for (UIImage *img in loaded) {
        CGFloat area = img.size.width * img.size.height * img.scale * img.scale;
        if (area > maxArea) { maxArea = area; best = img; }
    }
    return best;
}
@end

@implementation SNAppToggleCell

- (instancetype)initWithStyle:(UITableViewCellStyle)style
              reuseIdentifier:(NSString *)reuseIdentifier
                    specifier:(PSSpecifier *)specifier {
    self = [super initWithStyle:style reuseIdentifier:reuseIdentifier specifier:specifier];
    if (self) {
        self.textLabel.text   = nil;
        self.textLabel.hidden = YES;
        self.detailTextLabel.hidden = YES;
        
        _appIconView = [[UIImageView alloc] init];
        _appIconView.layer.cornerRadius  = 4.0;
        _appIconView.layer.masksToBounds = YES;
        _appIconView.contentMode = UIViewContentModeScaleAspectFit;
        [self.contentView addSubview:_appIconView];
        
        _appNameLabel = [[UILabel alloc] init];
        _appNameLabel.font = [UIFont boldSystemFontOfSize:16.0];
        _appNameLabel.backgroundColor = [UIColor clearColor];
        _appNameLabel.textColor = [UIColor blackColor];
        [self.contentView addSubview:_appNameLabel];
        
        _toggleSwitch = [[UISwitch alloc] initWithFrame:CGRectZero];
        _toggleSwitch.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin;
        [_toggleSwitch addTarget:self action:@selector(toggleChanged:)
                forControlEvents:UIControlEventValueChanged];
        self.accessoryView = _toggleSwitch;
        
        NSString *bundleId = [specifier propertyForKey:@"bundleId"];
        if (bundleId) [self configureCellForBundleId:bundleId];
    }
    return self;
}

- (void)layoutSubviews {
    [super layoutSubviews];
    CGFloat h = self.contentView.bounds.size.height;
    CGFloat iconSize = 30.0;
    
    _appIconView.frame = CGRectMake(15, (h - iconSize) / 2.0, iconSize, iconSize);
    
    CGFloat labelX = CGRectGetMaxX(_appIconView.frame) + 12.0;
    _appNameLabel.frame = CGRectMake(labelX, 0,
                                     self.contentView.bounds.size.width - labelX - 20.0, h);
    _appNameLabel.centerY = h / 2.0;
}

- (void)configureCellForBundleId:(NSString *)bundleId {
    AppInfoHelper *helper = [[AppInfoHelper alloc] init];
    
    UIImage *icon = [helper getIconForBundleId:bundleId];
    _appIconView.image = icon ?: [UIImage imageNamed:@"icon.png"];
    
    NSString *name = [helper getAppNameForBundleId:bundleId];
    _appNameLabel.text = name ?: bundleId;
    
    NSDictionary *appStatus = [[SNDataManager shared] appStatus];
    id val = [appStatus objectForKey:bundleId];
    if (val) {
        _toggleSwitch.on = [val boolValue];
    } else {
        NSSet *dbIDs = [[SNDataManager shared] registeredBundleIDs];
        _toggleSwitch.on = [dbIDs containsObject:bundleId];
    }
    
    self.selectionStyle = UITableViewCellSelectionStyleNone;
}

- (void)toggleChanged:(UISwitch *)sender {
    NSString *bundleId = [self.specifier propertyForKey:@"bundleId"];
    if (!bundleId) return;
    
    [[SNDataManager shared] setAppStatusValue:sender.isOn forBundleId:bundleId];
    NSLog(@"[SNAppToggleCell] %@ → %@", bundleId, sender.isOn ? @"ON" : @"OFF");
}

@end