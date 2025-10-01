#import "SNAppToggleCell.h"
#import <Preferences/Preferences.h> 

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@interface UIView (Center)
@property (nonatomic) CGFloat centerY;
@end

@implementation UIView (Center)
- (CGFloat)centerY {
    return self.center.y;
}
- (void)setCenterY:(CGFloat)centerY {
    CGPoint center = self.center;
    center.y = centerY;
    self.center = center;
}
@end

@interface AppInfoHelper : NSObject
- (UIImage *)getIconForBundleId:(NSString *)bundleId;
- (NSString *)getAppNameForBundleId:(NSString *)bundleId;
@end

@implementation AppInfoHelper

// Helper to cache MobileInstallation.plist
- (NSDictionary *)mobileInstallationPlist {
    static NSDictionary *cached = nil;
    if (!cached) {
        cached = [NSDictionary dictionaryWithContentsOfFile:
                  @"/var/mobile/Library/Caches/com.apple.mobile.installation.plist"];
    }
    return cached;
}

- (NSString *)getAppNameForBundleId:(NSString *)bundleId {
    NSDictionary *appInfo = [self mobileInstallationPlist];
    NSDictionary *userApps = appInfo[@"User"];
    NSDictionary *systemApps = appInfo[@"System"];
    
    NSDictionary *entry = userApps[bundleId];
    if (!entry) entry = systemApps[bundleId];
    if (!entry) return nil;
    
    NSString *displayName = entry[@"CFBundleDisplayName"];
    if (!displayName) displayName = entry[@"CFBundleName"];
    return displayName;
}

- (UIImage *)getIconForBundleId:(NSString *)bundleId {
    NSDictionary *appInfo = [self mobileInstallationPlist];
    NSDictionary *userApps = appInfo[@"User"];
    NSDictionary *systemApps = appInfo[@"System"];
    
    NSDictionary *entry = userApps[bundleId];
    if (!entry) entry = systemApps[bundleId];
    if (!entry) return nil;
    
    NSString *bundlePath = entry[@"Path"];
    if (!bundlePath) return nil;
    
    NSString *infoPlistPath = [bundlePath stringByAppendingPathComponent:@"Info.plist"];
    NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
    if (!infoPlist) return nil;
    
    NSMutableArray *loadedIcons = [NSMutableArray array];
    
    NSDictionary *iconsDict = infoPlist[@"CFBundleIcons"];
    if (iconsDict) {
        NSDictionary *primaryIcon = iconsDict[@"CFBundlePrimaryIcon"];
        NSArray *iconFiles = primaryIcon[@"CFBundleIconFiles"];
        for (NSString *iconName in iconFiles) {
            NSString *iconPath = [bundlePath stringByAppendingPathComponent:iconName];
            if (iconPath.pathExtension.length == 0) {
                iconPath = [iconPath stringByAppendingPathExtension:@"png"];
            }
            UIImage *img = [UIImage imageWithContentsOfFile:iconPath];
            if (img) [loadedIcons addObject:img];
        }
    } else {
        NSString *iconName = infoPlist[@"CFBundleIconFile"];
        if (iconName) {
            NSString *iconPath = [bundlePath stringByAppendingPathComponent:iconName];
            if (iconPath.pathExtension.length == 0) {
                iconPath = [iconPath stringByAppendingPathExtension:@"png"];
            }
            UIImage *img = [UIImage imageWithContentsOfFile:iconPath];
            if (img) [loadedIcons addObject:img];
        }
    }
    
    // Return the largest icon
    UIImage *largest = nil;
    CGFloat maxArea = 0.0;
    for (UIImage *img in loadedIcons) {
        CGFloat area = img.size.width * img.size.height * img.scale * img.scale;
        if (area > maxArea) {
            maxArea = area;
            largest = img;
        }
    }
    
    return largest;
}

@end


@implementation SNAppToggleCell


- (instancetype)initWithStyle:(UITableViewCellStyle)style reuseIdentifier:(NSString *)reuseIdentifier specifier:(PSSpecifier *)specifier {
    self = [super initWithStyle:style reuseIdentifier:reuseIdentifier specifier:specifier];
    if (self) {
        self.textLabel.text = nil;
        self.textLabel.hidden = YES;
        self.detailTextLabel.hidden = YES;
        // Set cell background to be transparent
        // self.backgroundColor = [UIColor clearColor];
        
        // Create app icon view with rounded corners
        _appIconView = [[UIImageView alloc] init];
        _appIconView.layer.cornerRadius = 4.0;
        _appIconView.layer.masksToBounds = YES;
        _appIconView.contentMode = UIViewContentModeScaleAspectFit;
        [self.contentView addSubview:_appIconView];
        
        // Create app name label with clear background
        _appNameLabel = [[UILabel alloc] init];
        _appNameLabel.font = [UIFont boldSystemFontOfSize:16.0];
        _appNameLabel.backgroundColor = [UIColor clearColor];
        _appNameLabel.textColor = [UIColor blackColor];
        [self.contentView addSubview:_appNameLabel];
        
        // Create toggle switch
        _toggleSwitch = [[UISwitch alloc] initWithFrame:CGRectZero];
        _toggleSwitch.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin;
        [_toggleSwitch addTarget:self action:@selector(toggleChanged:) forControlEvents:UIControlEventValueChanged];
        self.accessoryView = _toggleSwitch;
        
        // Configure cell with data from specifier
        NSString *bundleId = [specifier propertyForKey:@"bundleId"];
        if (bundleId) {
            [self configureCellForBundleId:bundleId];
        }
    }
    return self;
}

- (void)layoutSubviews {
    [super layoutSubviews];
    
    // Calculate proper vertical centering
    CGFloat cellHeight = self.contentView.bounds.size.height;
    CGFloat iconSize = 30.0;
    CGFloat padding = 15.0;
    
    // Center icon vertically
    _appIconView.frame = CGRectMake(
        padding,
        (cellHeight - iconSize) / 2.0,
        iconSize,
        iconSize
    );
    
    // Position label next to icon with proper spacing
    CGFloat labelX = CGRectGetMaxX(_appIconView.frame) + 12.0;
    _appNameLabel.frame = CGRectMake(
        labelX,
        0,
        self.contentView.bounds.size.width - labelX - 20.0, // Leave room for switch
        cellHeight
    );
    
    // Adjust label vertical centering
    _appNameLabel.centerY = cellHeight / 2.0;
}

- (void)configureCellForBundleId:(NSString *)bundleId {
    AppInfoHelper *helper = [[AppInfoHelper alloc] init];
    // Get app icon
    UIImage *icon = [helper getIconForBundleId:bundleId];
    if (icon) {
        _appIconView.image = icon;
    } else {
        // Default icon (gear icon for settings)
        _appIconView.image = [UIImage imageNamed:@"icon.png"];
    }
    
    // Get app name
    NSString *appName = [helper getAppNameForBundleId:bundleId];
    _appNameLabel.text = appName ? appName : bundleId;
    
    // Set toggle state from plist file
    NSDictionary *appStatus = [self getAppStatusFromPreferences];
    _toggleSwitch.on = [[appStatus objectForKey:bundleId] boolValue];
    
    // Ensure selection style is proper
    self.selectionStyle = UITableViewCellSelectionStyleNone;
}

- (NSDictionary *)getAppStatusFromPreferences {
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    return [prefs objectForKey:@"appStatus"] ?: [NSDictionary dictionary];
}

- (void)toggleChanged:(UISwitch *)sender {
    NSString *bundleId = [self.specifier propertyForKey:@"bundleId"];
    if (!bundleId) {
        NSLog(@"[SNAppToggleCell] Error: No bundle ID found in specifier");
        return;
    }
    
    // Get current app status from plist
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
    NSMutableDictionary *prefs;
    
    if ([[NSFileManager defaultManager] fileExistsAtPath:plistPath]) {
        prefs = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    } else {
        prefs = [NSMutableDictionary dictionary];
    }
    
    if (!prefs) {
        NSLog(@"[SNAppToggleCell] Error: Could not read preferences file");
        prefs = [NSMutableDictionary dictionary];
    }
    
    NSMutableDictionary *appStatus = [NSMutableDictionary dictionaryWithDictionary:[prefs objectForKey:@"appStatus"] ?: @{}];
    [appStatus setObject:@(sender.isOn) forKey:bundleId];
    [prefs setObject:appStatus forKey:@"appStatus"];
    
    // Try to write to file and check if successful
    BOOL writeSuccess = [prefs writeToFile:plistPath atomically:YES];
    if (!writeSuccess) {
        NSLog(@"[SNAppToggleCell] Error: Failed to write preferences to %@", plistPath);
        // Revert switch state if save failed
        sender.on = !sender.on;
        return;
    }
    
    NSLog(@"[SNAppToggleCell] Successfully toggled %@ to %@", bundleId, sender.isOn ? @"ON" : @"OFF");
}

@end