#import "SNAppToggleCell.h"
#import "SNInterfaceColors.h"
#import "SNDataManager.h"
#import "SNChannelGateway.h"
#import <Preferences/PSSpecifier.h>
#import <Preferences/PSTableCell.h>
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>

@interface NSObject (SNLaunchServicesApplicationMetadata)
+ (id)applicationProxyForIdentifier:(NSString *)bundleIdentifier;
- (NSString *)localizedName;
- (NSString *)itemName;
- (id)iconDataForVariant:(NSInteger)variant;
@end

@interface UIImage (SNApplicationIconProvider)
+ (UIImage *)_applicationIconImageForBundleIdentifier:
    (NSString *)bundleIdentifier format:(NSInteger)format scale:(CGFloat)scale;
@end

static Class SNApplicationProxyClass(void) {
    Class proxyClass = NSClassFromString(@"LSApplicationProxy");
    if (proxyClass) return proxyClass;

    for (NSString *path in @[
        @"/System/Library/Frameworks/CoreServices.framework",
        @"/System/Library/Frameworks/MobileCoreServices.framework"
    ]) {
        [[NSBundle bundleWithPath:path] load];
        proxyClass = NSClassFromString(@"LSApplicationProxy");
        if (proxyClass) break;
    }
    return proxyClass;
}

static UIImage *SNImageFromIconRepresentation(id representation) {
    if ([representation isKindOfClass:[UIImage class]]) return representation;
    if ([representation isKindOfClass:[NSData class]]) {
        return [UIImage imageWithData:representation];
    }
    if ([representation isKindOfClass:[NSArray class]]) {
        for (id item in representation) {
            UIImage *image = SNImageFromIconRepresentation(item);
            if (image) return image;
        }
    }
    return nil;
}

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

- (id)modernApplicationProxyForBundleId:(NSString *)bundleId {
    Class proxyClass = SNApplicationProxyClass();
    return [proxyClass respondsToSelector:
        @selector(applicationProxyForIdentifier:)]
        ? [proxyClass applicationProxyForIdentifier:bundleId] : nil;
}

- (NSDictionary *)mobileInstallationPlist {
    static NSDictionary *cached = nil;
    if (!cached) {
        cached = [[NSDictionary alloc] initWithContentsOfFile:
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
    id proxy = [self modernApplicationProxyForBundleId:bundleId];
    NSString *name = [proxy respondsToSelector:@selector(localizedName)]
        ? [proxy localizedName] : nil;
    if (![name length] && [proxy respondsToSelector:@selector(itemName)]) {
        name = [proxy itemName];
    }
    if ([name length]) return name;

    NSDictionary *entry = [self entryForBundleId:bundleId];
    if (!entry) return nil;
    return entry[@"CFBundleDisplayName"] ?: entry[@"CFBundleName"];
}

- (UIImage *)getIconForBundleId:(NSString *)bundleId {
    id proxy = [self modernApplicationProxyForBundleId:bundleId];
    if ([proxy respondsToSelector:@selector(iconDataForVariant:)]) {
        for (NSNumber *variant in @[@2, @0, @1]) {
            UIImage *image = SNImageFromIconRepresentation(
                [proxy iconDataForVariant:[variant integerValue]]);
            if (image) return image;
        }
    }

    SEL iconSelector = @selector(
        _applicationIconImageForBundleIdentifier:format:scale:);
    if ([UIImage respondsToSelector:iconSelector]) {
        CGFloat scale = [[UIScreen mainScreen] scale];
        for (NSNumber *format in @[@0, @2, @1]) {
            UIImage *image = [UIImage
                _applicationIconImageForBundleIdentifier:bundleId
                                                   format:[format integerValue]
                                                    scale:scale];
            if (image) return image;
        }
    }

    /* Legacy fallback: icon artwork from the application bundle. */
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

@implementation SNAppToggleCell {
    /* PSTableCell on iOS 4 lacks -specifier. */
    PSSpecifier *_sgnSpecifier;
}

- (instancetype)initWithStyle:(UITableViewCellStyle)style
              reuseIdentifier:(NSString *)reuseIdentifier
                    specifier:(PSSpecifier *)specifier {
    self = [super initWithStyle:style reuseIdentifier:reuseIdentifier specifier:specifier];
    if (self) {
        _sgnSpecifier = [specifier retain];
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
        _appNameLabel.textColor = SNLabelColor([UIColor blackColor]);
        [self.contentView addSubview:_appNameLabel];

        NSString *bundleId = [specifier propertyForKey:@"bundleId"];
        if (bundleId) [self configureCellForBundleId:bundleId];
    }
    return self;
}

/* PSSwitchCell adds its own UISwitch after init; remove strays. */
- (void)_sgnRemoveStraySwitchesIn:(UIView *)root {
    for (UIView *sub in [[root.subviews copy] autorelease]) {
        if ([sub isKindOfClass:[UISwitch class]]) {
            if (sub != _toggleSwitch) [sub removeFromSuperview];
        } else {
            [self _sgnRemoveStraySwitchesIn:sub];
        }
    }
}

- (void)layoutSubviews {
    [super layoutSubviews];

    BOOL hideToggle = [[_sgnSpecifier propertyForKey:@"sgnHideToggle"] boolValue];
    [self _sgnRemoveStraySwitchesIn:self];
    if (!hideToggle && _toggleSwitch && self.accessoryView != _toggleSwitch) {
        self.accessoryView = _toggleSwitch;
    }

    CGFloat h = self.contentView.bounds.size.height;
    CGFloat iconSize = 32.0;

    _appIconView.frame = CGRectMake(6, (h - iconSize) / 2.0, iconSize, iconSize);

    CGFloat labelX = CGRectGetMaxX(_appIconView.frame) + 11.0;
    _appNameLabel.frame = CGRectMake(labelX, 0,
                                     self.contentView.bounds.size.width - labelX - 20.0, h);
    _appNameLabel.centerY = h / 2.0;
}


- (void)setControl:(id)control {}
- (id)control { return nil; }

- (void)controlChanged:(id)control {
    if ([control isKindOfClass:[UISwitch class]]) {
        [self toggleChanged:(UISwitch *)control];
    }
}

- (void)refreshCellContentsWithSpecifier:(PSSpecifier *)specifier {
    [super refreshCellContentsWithSpecifier:specifier];
    if (_sgnSpecifier != specifier) {
        [_sgnSpecifier release];
        _sgnSpecifier = [specifier retain];
    }
    NSString *bundleId = [specifier propertyForKey:@"bundleId"];
    if (bundleId) [self configureCellForBundleId:bundleId];
    [self syncAccessoryState];
}

- (void)syncAccessoryState {
    BOOL deleting = [[_sgnSpecifier propertyForKey:@"sgnDeleting"] boolValue];
    BOOL toggling = [[_sgnSpecifier propertyForKey:@"sgnToggling"] boolValue];
    BOOL hideToggle = [[_sgnSpecifier propertyForKey:@"sgnHideToggle"] boolValue];
    self.userInteractionEnabled = !(deleting || toggling);

    if (deleting || toggling) {
        if (!_activityIndicator) {
            _activityIndicator = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
        }
        [_activityIndicator startAnimating];
        self.accessoryView = _activityIndicator;
        return;
    }

    [_activityIndicator stopAnimating];
    if (hideToggle) {
        self.accessoryView = nil;
        [self _sgnRemoveStraySwitchesIn:self];
        return;
    }

    if (!_toggleSwitch) {
        _toggleSwitch = [[UISwitch alloc] initWithFrame:CGRectZero];
        _toggleSwitch.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin;
        [_toggleSwitch addTarget:self action:@selector(toggleChanged:)
                forControlEvents:UIControlEventValueChanged];
    }
    [self _sgnRemoveStraySwitchesIn:self];
    self.accessoryView = _toggleSwitch;
}

- (void)setDeletingAccessoryVisible:(BOOL)deleting {
    [_sgnSpecifier setProperty:@(deleting) forKey:@"sgnDeleting"];
    [self syncAccessoryState];
}

- (void)setTogglePending:(BOOL)pending {
    [_sgnSpecifier setProperty:@(pending) forKey:@"sgnToggling"];
    [self syncAccessoryState];
}

- (void)configureCellForBundleId:(NSString *)bundleId {
    AppInfoHelper *helper = [[AppInfoHelper alloc] init];

    UIImage *icon = [helper getIconForBundleId:bundleId];
    _appIconView.image = icon ?: [UIImage imageNamed:@"icon.png"];

    NSString *name = [helper getAppNameForBundleId:bundleId];
    _appNameLabel.text = name ?: bundleId;

    [helper release];

    [self syncAccessoryState];

    if (_toggleSwitch) {
        NSDictionary *appStatus = [[SNDataManager shared] appStatus];
        id val = [appStatus objectForKey:bundleId];
        if (val) {
            _toggleSwitch.on = [val boolValue];
        } else {
            NSSet *dbIDs = [[SNDataManager shared] registeredBundleIDs];
            _toggleSwitch.on = [dbIDs containsObject:bundleId];
        }
    }

    self.selectionStyle = UITableViewCellSelectionStyleNone;
}

- (void)toggleChanged:(UISwitch *)sender {
    NSString *bundleId = [_sgnSpecifier propertyForKey:@"bundleId"];
    if (!bundleId) return;

    BOOL desired = sender.isOn;
    [self setTogglePending:YES];

    PSSpecifier *requestSpecifier = [_sgnSpecifier retain];
    NSString *requestBundleID = [bundleId copy];
    SNChannelCommandCompletion done = ^(BOOL ok, NSString *message) {
        [requestSpecifier setProperty:@NO forKey:@"sgnToggling"];

        if (_sgnSpecifier == requestSpecifier) {
            [self syncAccessoryState];
            if (!ok) {
                [_toggleSwitch setOn:!desired animated:YES];
            }
        }
        [requestSpecifier release];
        [requestBundleID release];
    };

    if (desired) {
        [SNChannelGateway enableAppForBundleId:requestBundleID completion:done];
    } else {
        [SNChannelGateway disableAppForBundleId:requestBundleID completion:done];
    }
}

- (void)dealloc {
    [_sgnSpecifier release];
    [_appIconView release];
    [_appNameLabel release];
    [_toggleSwitch release];
    [_activityIndicator release];
    [super dealloc];
}

@end
