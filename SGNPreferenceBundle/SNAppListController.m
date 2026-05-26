#import "SNAppListController.h"
#import "SNDataManager.h"
#import "SNChannelGateway.h"
#import <Preferences/PSSpecifier.h>
#import <Preferences/PSTableCell.h>
#import "SNAppToggleCell.h"

static NSString * const kSGNSectionPropKey = @"sgnSection";
static NSString * const kSGNSectionSkyglow = @"skyglow";
static NSString * const kSGNSectionAPNs    = @"apns";
static NSString * const kSGNSectionGroupPropKey = @"sgnSectionGroup";
static NSString * const kSGNPlaceholderPropKey  = @"sgnPlaceholder";

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
        NSArray *pending = [dm pendingDeletions] ?: @[];
        NSMutableSet *exclude = [NSMutableSet setWithArray:[appStatus allKeys]];
        [exclude unionSet:dbBundleIDs];
        [exclude addObjectsFromArray:pending];

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
    PSSpecifier *groupSpec = [PSSpecifier preferenceSpecifierNamed:@"Toggle Notifications"
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
    NSArray      *pending      = [dm pendingDeletions];

    NSMutableSet *allBundleIDs = [NSMutableSet setWithArray:[appStatus allKeys]];
    [allBundleIDs unionSet:dbBundleIDs];
    if (pending.count > 0) {
        [allBundleIDs minusSet:[NSSet setWithArray:pending]];
    }

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
        [groupSpec setProperty:@"Toggle to mute Skyglow notifications for an app. Swipe to forget, the app will prompt you for a provider next time it asks for notifications."
                        forKey:@"footerText"];
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

    [groupSpec setProperty:@"Toggle to mute Skyglow notifications for an app. Swipe to forget, the app will prompt you for a provider next time it asks for notifications."
                    forKey:@"footerText"];
}

- (void)_buildAPNsSectionInto:(NSMutableArray *)specs {
    if (self.apsdBundles.count == 0) return;

    PSSpecifier *groupSpec = [PSSpecifier preferenceSpecifierNamed:@"Apps Using Apple Push"
                                                            target:self
                                                               set:NULL
                                                               get:NULL
                                                            detail:Nil
                                                              cell:PSGroupCell
                                                              edit:Nil];
    [groupSpec setProperty:@YES forKey:@"isDeletionGroup"];
    [groupSpec setProperty:kSGNSectionAPNs forKey:kSGNSectionPropKey];
    [groupSpec setProperty:@YES forKey:kSGNSectionGroupPropKey];
    [groupSpec setProperty:@"These apps were registered for push notifications before Skyglow was installed, or you picked Apple Push for them. Swipe to forget, the app will prompt you for a provider next time it asks for notifications."
                    forKey:@"footerText"];
    [specs addObject:groupSpec];

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

- (PSSpecifier *)_groupSpecifierForSection:(NSString *)section {
    for (PSSpecifier *candidate in [self specifiers]) {
        if ([[candidate propertyForKey:kSGNSectionPropKey] isEqualToString:section] &&
            [[candidate propertyForKey:kSGNSectionGroupPropKey] boolValue]) {
            return candidate;
        }
    }
    return nil;
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
        [self insertSpecifier:[self _skyglowEmptyPlaceholderSpecifier]
               afterSpecifier:group
                     animated:YES];
    } else if ([section isEqualToString:kSGNSectionAPNs] && group) {
        [self removeSpecifier:group animated:YES];
    }
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

    if ([section isEqualToString:kSGNSectionAPNs]) {
        [SNChannelGateway postDeleteAppForBundleId:bundleId];
        [self _removeBundleSpecifier:spec section:section bundleId:bundleId];
        return;
    }

    [[SNDataManager shared] scheduleAppDeletion:bundleId];
    [SNChannelGateway postDeleteAppForBundleId:bundleId];
    [self _removeBundleSpecifier:spec section:section bundleId:bundleId];
}

@end
