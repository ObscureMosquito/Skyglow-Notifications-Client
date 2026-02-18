#import "SNAppListController.h"
#import <Preferences/PSSpecifier.h>
#import <Preferences/PSTableCell.h>
#import "SNAppToggleCell.h"

@implementation SNAppListController


- (NSArray *)specifiers {
    NSLog(@"Getting app list specifiers");
    if (!_specifiers) {
        NSMutableArray *specs = [NSMutableArray array];
        
        // Add header
        PSSpecifier *groupSpecifier = [PSSpecifier preferenceSpecifierNamed:@"Toggle Notifications per app"
                                                                     target:self
                                                                        set:NULL
                                                                        get:NULL
                                                                     detail:Nil
                                                                       cell:PSGroupCell
                                                                       edit:Nil];
        [groupSpecifier setProperty:@"If enabled, Skyglow notifications will be used for sending notifications. If it's off, apple's built in notification service will be used for that app." forKey:@"footerText"];
        [specs addObject:groupSpecifier];
        
        NSDictionary *appStatus = [self getAppStatusFromPreferences];
        
        if (!appStatus || appStatus.count == 0) {
            // If no apps configured yet, show placeholder
            PSSpecifier *placeholderSpec = [PSSpecifier preferenceSpecifierNamed:@"No regisered applications."
                                                                         target:self
                                                                            set:NULL
                                                                            get:NULL
                                                                         detail:Nil
                                                                           cell:PSStaticTextCell
                                                                           edit:Nil];
            [specs addObject:placeholderSpec];
        } else {
            for (NSString *bundleId in appStatus) {
                PSSpecifier *spec = [PSSpecifier preferenceSpecifierNamed:bundleId
                                                                 target:self
                                                                    set:@selector(setPreferenceValue:specifier:)
                                                                    get:@selector(readPreferenceValue:)
                                                                 detail:Nil
                                                                   cell:PSSwitchCell
                                                                   edit:Nil];
                
                [spec setProperty:bundleId forKey:@"bundleId"];
                [spec setProperty:[SNAppToggleCell class] forKey:@"cellClass"];
                [spec setProperty:@"com.skyglow.sndp" forKey:@"defaults"];
                [spec setProperty:@"appStatus" forKey:@"key"];
                [specs addObject:spec];
                
        
            }
            [groupSpecifier setProperty:@"Not seeing the app you want to toggle? Try opening it or signing into your app to get it to appear on this list." forKey:@"footerText"];
        }
        _specifiers = [specs copy];
        
    }
    
    return _specifiers;
}

- (id)readPreferenceValue:(PSSpecifier*)specifier {
    NSString *bundleId = [specifier propertyForKey:@"bundleId"];
    NSLog(@"[SNAppListController] Reading preference for %@", bundleId);
    
    NSDictionary *appStatus = [self getAppStatusFromPreferences];
    return [appStatus objectForKey:bundleId] ?: @NO;
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier*)specifier {
    NSString *bundleId = [specifier propertyForKey:@"bundleId"];
    NSLog(@"[SNAppListController] Setting %@ to %@", bundleId, value);
    
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath] ?: [NSMutableDictionary dictionary];
    NSMutableDictionary *appStatus = [NSMutableDictionary dictionaryWithDictionary:[prefs objectForKey:@"appStatus"] ?: @{}];
    
    [appStatus setObject:value forKey:bundleId];
    [prefs setObject:appStatus forKey:@"appStatus"];
    
    BOOL success = [prefs writeToFile:plistPath atomically:YES];
    NSLog(@"[SNAppListController] Write success: %d", success);
    
                                      
    [self reloadSpecifier:specifier animated:YES];
}

- (NSDictionary *)getAppStatusFromPreferences {
    NSString *plistPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    return [prefs objectForKey:@"appStatus"];
}

@end