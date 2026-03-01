#import "SNAppListController.h"
#import "SNDataManager.h"
#import <Preferences/PSSpecifier.h>
#import <Preferences/PSTableCell.h>
#import "SNAppToggleCell.h"

@implementation SNAppListController

- (NSArray *)specifiers {
    if (!_specifiers) {
        NSMutableArray *specs = [NSMutableArray array];
        
        PSSpecifier *groupSpec = [PSSpecifier preferenceSpecifierNamed:@"Toggle Notifications per app"
                                                                target:self
                                                                   set:NULL
                                                                   get:NULL
                                                                  detail:Nil
                                                                    cell:PSGroupCell
                                                                    edit:Nil];
        [groupSpec setProperty:@YES forKey:@"isDeletionGroup"];
        
        [specs addObject:groupSpec];
        
        SNDataManager *dm = [SNDataManager shared];
        NSDictionary *appStatus    = [dm appStatus];
        NSSet        *dbBundleIDs  = [dm registeredBundleIDs];
        
        NSMutableSet *allBundleIDs = [NSMutableSet setWithArray:[appStatus allKeys]];
        [allBundleIDs unionSet:dbBundleIDs];
        
        if ([allBundleIDs count] == 0) {
            PSSpecifier *placeholder = [PSSpecifier preferenceSpecifierNamed:@"No registered applications."
                                                                      target:self
                                                                         set:NULL
                                                                         get:NULL
                                                                      detail:Nil
                                                                        cell:PSStaticTextCell
                                                                        edit:Nil];
            [specs addObject:placeholder];
            [groupSpec setProperty:@"If enabled, Skyglow notifications will be used for sending notifications. If it's off, Apple's built in notification service will be used for that app."
                            forKey:@"footerText"];
        } else {
            NSArray *sorted = [[allBundleIDs allObjects] sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];
            
            for (NSString *bundleId in sorted) {
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
            
            [groupSpec setProperty:@"Not seeing the app you want? Try opening it or signing in to get it to appear."
                            forKey:@"footerText"];
        }
        
        _specifiers = [specs copy];
    }
    return _specifiers;
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
    NSString *bundleId = [specifier propertyForKey:@"bundleId"];
    NSDictionary *appStatus = [[SNDataManager shared] appStatus];
    id val = [appStatus objectForKey:bundleId];
    
    if (val == nil) {
        NSSet *dbIDs = [[SNDataManager shared] registeredBundleIDs];
        if ([dbIDs containsObject:bundleId]) {
            return @YES;
        }
    }
    return val ?: @NO;
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier {
    NSString *bundleId = [specifier propertyForKey:@"bundleId"];
    if (!bundleId) return;
    
    [[SNDataManager shared] setAppStatusValue:[value boolValue] forBundleId:bundleId];
    [self reloadSpecifier:specifier animated:YES];
}

- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath {
    if (indexPath.section < _specifiers.count) {
        PSSpecifier *spec = [self specifierAtIndex:[self indexForIndexPath:indexPath]];
        if ([spec propertyForKey:@"bundleId"]) {
            return YES;
        }
    }
    return NO;
}

- (void)tableView:(UITableView *)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle forRowAtIndexPath:(NSIndexPath *)indexPath {
    if (editingStyle == UITableViewCellEditingStyleDelete) {
        PSSpecifier *spec = [self specifierAtIndex:[self indexForIndexPath:indexPath]];
        NSString *bundleId = [spec propertyForKey:@"bundleId"];
        
        if (bundleId) {
            NSDictionary *prefs = [[NSUserDefaults standardUserDefaults] persistentDomainForName:@"com.skyglow.sndp"] ?: @{};
            NSMutableDictionary *mutablePrefs = [prefs mutableCopy];
            [mutablePrefs setObject:bundleId forKey:@"lastUnregisteredApp"];
            [[NSUserDefaults standardUserDefaults] setPersistentDomain:mutablePrefs forName:@"com.skyglow.sndp"];
            [[NSUserDefaults standardUserDefaults] synchronize];

            CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                                 CFSTR("com.skyglow.sgn.unregisterInputApp"),
                                                 NULL, NULL, TRUE);
            
            [[SNDataManager shared] removeAppStatusForBundleId:bundleId];
            [[SNDataManager shared] removeAppFromDatabase:bundleId];
            
            [self removeSpecifier:spec animated:YES];
        }
    }
}

@end