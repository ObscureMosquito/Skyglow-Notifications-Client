#import "SNAppListController.h"
#import "SNDataManager.h"
#import "SNChannelGateway.h"
#import <Preferences/PSSpecifier.h>
#import <Preferences/PSTableCell.h>
#import <UIKit/UIKit.h>
#import "SNAppToggleCell.h"

static NSString * const kSGNSectionPropKey = @"sgnSection";
static NSString * const kSGNSectionSkyglow = @"skyglow";
static NSString * const kSGNSectionAPNs    = @"apns";
static NSString * const kSGNSectionGroupPropKey = @"sgnSectionGroup";
static NSString * const kSGNPlaceholderPropKey  = @"sgnPlaceholder";
static NSString * const kSGNSkyglowEmptyFooter = @"Applications that have registered with Skyglow Notifications will appear here.";
static NSString * const kSGNAPNsEmptyFooter = @"Applications that have registered with Apple Push Notifications will appear here.";
static NSString * const kSGNSkyglowPopulatedFooter = @"Toggle to mute Skyglow notifications for an app. Swipe to forget, the app will prompt you for a provider next time it asks for notifications.";
static NSString * const kSGNAPNsPopulatedFooter = @"These apps were registered with Apple Push for notifications. Swipe to forget, the app will prompt you for a provider next time it opens.";

@interface SNAppListController ()
@property (nonatomic, strong) NSArray *apsdBundles;
@end

@implementation SNAppListController

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self _refreshAPNsList];
}

- (void)_refreshAPNsList {
    [SNChannelGateway queryNativelyPushRegisteredBundlesWithCompletion:^(NSArray *bundleIds) {
        SNDataManager *dm = [SNDataManager shared];
        NSDictionary *appStatus = [dm appStatus] ?: @{};
        NSSet *dbBundleIDs = [dm registeredBundleIDs] ?: [NSSet set];
        NSMutableSet *exclude = [NSMutableSet setWithArray:[appStatus allKeys]];
        [exclude unionSet:dbBundleIDs];

        NSMutableArray *filtered = [NSMutableArray array];
        for (NSString *bid in bundleIds) {
            if (![exclude containsObject:bid]) [filtered addObject:bid];
        }
        NSArray *sorted = [filtered sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];

        if (self.apsdBundles && [self.apsdBundles isEqualToArray:sorted]) return;
        self.apsdBundles = sorted;
        [self reloadSpecifiers];
    }];
}

- (NSArray *)specifiers {
    if (!_specifiers) {
        NSMutableArray *specs = [NSMutableArray array];

        [self _buildSkyglowSectionInto:specs];
        [self _buildAPNsSectionInto:specs];

        _specifiers = [specs copy];
    }
    return _specifiers;
}

- (void)_buildSkyglowSectionInto:(NSMutableArray *)specs {
    PSSpecifier *groupSpec = [PSSpecifier preferenceSpecifierNamed:@"Skyglow Notifications"
                                                            target:self
                                                               set:NULL
                                                               get:NULL
                                                            detail:Nil
                                                              cell:PSGroupCell
                                                              edit:Nil];
    [groupSpec setProperty:@YES forKey:@"isDeletionGroup"];
    [groupSpec setProperty:kSGNSectionSkyglow forKey:kSGNSectionPropKey];
    [groupSpec setProperty:@YES forKey:kSGNSectionGroupPropKey];
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
        [placeholder setProperty:kSGNSectionSkyglow forKey:kSGNSectionPropKey];
        [placeholder setProperty:@YES forKey:kSGNPlaceholderPropKey];
        [specs addObject:placeholder];
        [groupSpec setProperty:kSGNSkyglowEmptyFooter forKey:@"footerText"];
        return;
    }

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
        [spec setProperty:kSGNSectionSkyglow forKey:kSGNSectionPropKey];
        [specs addObject:spec];
    }

    [groupSpec setProperty:kSGNSkyglowPopulatedFooter forKey:@"footerText"];
}

- (void)_buildAPNsSectionInto:(NSMutableArray *)specs {
    PSSpecifier *groupSpec = [PSSpecifier preferenceSpecifierNamed:@"Apple Push Notifications"
                                                            target:self
                                                               set:NULL
                                                               get:NULL
                                                            detail:Nil
                                                              cell:PSGroupCell
                                                              edit:Nil];
    [groupSpec setProperty:@YES forKey:@"isDeletionGroup"];
    [groupSpec setProperty:kSGNSectionAPNs forKey:kSGNSectionPropKey];
    [groupSpec setProperty:@YES forKey:kSGNSectionGroupPropKey];
    [specs addObject:groupSpec];

    if (self.apsdBundles.count == 0) {
        [groupSpec setProperty:kSGNAPNsEmptyFooter forKey:@"footerText"];
        PSSpecifier *placeholder = [PSSpecifier preferenceSpecifierNamed:@"No registered applications."
                                                                  target:self
                                                                     set:NULL
                                                                     get:NULL
                                                                  detail:Nil
                                                                    cell:PSStaticTextCell
                                                                    edit:Nil];
        [placeholder setProperty:kSGNSectionAPNs forKey:kSGNSectionPropKey];
        [placeholder setProperty:@YES forKey:kSGNPlaceholderPropKey];
        [specs addObject:placeholder];
        return;
    }

    [groupSpec setProperty:kSGNAPNsPopulatedFooter forKey:@"footerText"];

    for (NSString *bundleId in self.apsdBundles) {
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
        [spec setProperty:@YES forKey:@"sgnHideToggle"];
        [spec setProperty:kSGNSectionAPNs forKey:kSGNSectionPropKey];
        [specs addObject:spec];
    }
}

- (PSSpecifier *)_skyglowEmptyPlaceholderSpecifier {
    PSSpecifier *placeholder = [PSSpecifier preferenceSpecifierNamed:@"No registered applications."
                                                              target:self
                                                                 set:NULL
                                                                 get:NULL
                                                              detail:Nil
                                                                cell:PSStaticTextCell
                                                                edit:Nil];
    [placeholder setProperty:kSGNSectionSkyglow forKey:kSGNSectionPropKey];
    [placeholder setProperty:@YES forKey:kSGNPlaceholderPropKey];
    return placeholder;
}

- (PSSpecifier *)_apnsEmptyPlaceholderSpecifier {
    PSSpecifier *placeholder = [PSSpecifier preferenceSpecifierNamed:@"No registered applications."
                                                              target:self
                                                                 set:NULL
                                                                 get:NULL
                                                              detail:Nil
                                                                cell:PSStaticTextCell
                                                                edit:Nil];
    [placeholder setProperty:kSGNSectionAPNs forKey:kSGNSectionPropKey];
    [placeholder setProperty:@YES forKey:kSGNPlaceholderPropKey];
    return placeholder;
}

- (PSSpecifier *)_groupSpecifierForSection:(NSString *)section {
    for (PSSpecifier *candidate in [self specifiers]) {
        if ([[candidate propertyForKey:kSGNSectionPropKey] isEqualToString:section] &&
            [[candidate propertyForKey:kSGNSectionGroupPropKey] boolValue]) {
            return candidate;
        }
    }
    return nil;
}

- (void)_setEmptyFooterForGroup:(PSSpecifier *)group section:(NSString *)section {
    NSString *footer = [section isEqualToString:kSGNSectionAPNs] ? kSGNAPNsEmptyFooter : kSGNSkyglowEmptyFooter;
    [group setProperty:footer forKey:@"footerText"];
    [self reloadSpecifier:group animated:YES];
}

- (NSUInteger)_bundleRowCountForSection:(NSString *)section excludingSpecifier:(PSSpecifier *)excluded {
    NSUInteger count = 0;
    for (PSSpecifier *candidate in [self specifiers]) {
        if (candidate == excluded) continue;
        if (![candidate propertyForKey:@"bundleId"]) continue;
        if ([[candidate propertyForKey:kSGNSectionPropKey] isEqualToString:section]) count++;
    }
    return count;
}

- (void)_removeAPNsBundleFromCachedList:(NSString *)bundleId {
    if (!bundleId.length || self.apsdBundles.count == 0) return;
    NSMutableArray *next = [NSMutableArray arrayWithArray:self.apsdBundles];
    [next removeObject:bundleId];
    self.apsdBundles = next;
}

- (void)_removeBundleSpecifier:(PSSpecifier *)specifier
                       section:(NSString *)section
                      bundleId:(NSString *)bundleId {
    BOOL wasLastBundleRow = ([self _bundleRowCountForSection:section excludingSpecifier:specifier] == 0);

    if ([section isEqualToString:kSGNSectionAPNs]) {
        [self _removeAPNsBundleFromCachedList:bundleId];
    }

    if (!wasLastBundleRow) {
        [self removeSpecifier:specifier animated:YES];
        return;
    }

    PSSpecifier *group = [self _groupSpecifierForSection:section];
    [self removeSpecifier:specifier animated:YES];

    if ([section isEqualToString:kSGNSectionSkyglow] && group) {
        [self _setEmptyFooterForGroup:group section:section];
        [self insertSpecifier:[self _skyglowEmptyPlaceholderSpecifier]
               afterSpecifier:group
                     animated:YES];
    } else if ([section isEqualToString:kSGNSectionAPNs] && group) {
        [self _setEmptyFooterForGroup:group section:section];
        [self insertSpecifier:[self _apnsEmptyPlaceholderSpecifier]
               afterSpecifier:group
                     animated:YES];
    }
}

- (void)_showDeletionErrorForBundleId:(NSString *)bundleId message:(NSString *)message {
    NSString *title = @"Could Not Forget App";
    NSString *body = message.length ? message : @"Could not communicate with SpringBoard. Try again after respringing.";
    if (bundleId.length) {
        body = [NSString stringWithFormat:@"%@\n\n%@", bundleId, body];
    }

    [[[UIAlertView alloc] initWithTitle:title
                                message:body
                               delegate:nil
                      cancelButtonTitle:@"OK"
                      otherButtonTitles:nil] show];
}

- (UITableViewCellEditingStyle)tableView:(UITableView *)tableView editingStyleForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (indexPath.section < _specifiers.count) {
        PSSpecifier *spec = [self specifierAtIndex:[self indexForIndexPath:indexPath]];
        if ([spec propertyForKey:@"bundleId"]) {
            return UITableViewCellEditingStyleDelete;
        }
    }
    return UITableViewCellEditingStyleNone;
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

    BOOL on = [value boolValue];
    [[SNDataManager shared] setAppStatusValue:on forBundleId:bundleId];
    if (on) {
        [SNChannelGateway postEnableAppForBundleId:bundleId];
    } else {
        [SNChannelGateway postDisableAppForBundleId:bundleId];
    }
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
    if (editingStyle != UITableViewCellEditingStyleDelete) return;
    PSSpecifier *spec = [self specifierAtIndex:[self indexForIndexPath:indexPath]];
    NSString *bundleId = [spec propertyForKey:@"bundleId"];
    if (!bundleId) return;

    NSString *section = [spec propertyForKey:kSGNSectionPropKey];
    [tableView setEditing:NO animated:YES];

    [SNChannelGateway deleteAppForBundleId:bundleId completion:^(BOOL ok, NSString *message) {
        if (!ok) {
            [self _showDeletionErrorForBundleId:bundleId message:message];
            return;
        }

        if ([section isEqualToString:kSGNSectionSkyglow]) {
            [[SNDataManager shared] removeAppStatusForBundleId:bundleId];
        }
        [self _removeBundleSpecifier:spec section:section bundleId:bundleId];
    }];
}

@end
