#import <UIKit/UIKit.h>
#import <Preferences/PSSpecifier.h>
#import <Preferences/PSTableCell.h>
#import <Preferences/PSListController.h>
#import <Preferences/PSRootController.h>


static NSString *const kSkyglowID = @"SkyglowNotificationsID";
static NSString *const kSGNBundleObjKey  = @"sgn_bundle_obj";
static NSString *const kSGNPlistNameKey  = @"sgn_plist_name";

@interface SGNCustomListController : PSListController
@end

@implementation SGNCustomListController

- (NSBundle *)bundle {
    NSBundle *b = [self.specifier propertyForKey:kSGNBundleObjKey];
    return b ?: [super bundle];
}

- (id)specifiers {
    if (!_specifiers) {
        NSString *plist = [self.specifier propertyForKey:kSGNPlistNameKey];
        if (!plist.length) plist = @"Root";

        _specifiers = [self loadSpecifiersFromPlistName:plist target:self];
    }
    return _specifiers;
}

- (id)navigationTitle {
    return self.specifier.name;
}

@end

%hook PrefsListController

- (NSMutableArray *)specifiers {
    NSMutableArray *specifiers = %orig;
    if (!specifiers) return specifiers;

    for (PSSpecifier *spec in specifiers) {
        if ([[spec identifier] isEqualToString:kSkyglowID]) return specifiers;
    }

    NSUInteger insertIndex = 2;
    for (NSUInteger i = 0; i < specifiers.count; i++) {
        NSString *ident = [specifiers[i] identifier];
        if ([ident isEqualToString:@"NOTIFICATIONS"] || [ident isEqualToString:@"NOTIFICATIONS_ID"]) {
            insertIndex = i + 1;
            break;
        }
    }

    NSString *bundlePath = @"/Library/PreferenceBundles/SkyglowNotificationsDaemonSettings.bundle";
	NSBundle *prefBundle = [NSBundle bundleWithPath:bundlePath];
	[prefBundle load];
	Class rootCls = [prefBundle principalClass];
	if (!rootCls) rootCls = [prefBundle classNamed:@"SNRootListController"];

	PSSpecifier *skyglowSpec =
	[PSSpecifier preferenceSpecifierNamed:@"Skyglow Notifications"
									target:nil
										set:NULL
										get:NULL
									detail:rootCls
									cell:PSLinkCell
									edit:nil];

    [skyglowSpec setIdentifier:kSkyglowID];

    // Carry the bundle object just like PLBundleKey does in PreferenceLoader
    if (prefBundle) [skyglowSpec setProperty:prefBundle forKey:kSGNBundleObjKey];

    [skyglowSpec setProperty:@"Root" forKey:kSGNPlistNameKey];

    UIImage *icon = [UIImage imageWithContentsOfFile:[bundlePath stringByAppendingPathComponent:@"icon.png"]];
    if (icon) [skyglowSpec setProperty:icon forKey:@"iconImage"];

    if (insertIndex < specifiers.count) [specifiers insertObject:skyglowSpec atIndex:insertIndex];
    else [specifiers addObject:skyglowSpec];

    return specifiers;
}

%end
