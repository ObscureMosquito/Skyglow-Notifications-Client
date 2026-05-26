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
static NSString * const kSGNDeletingPropKey = @"sgnDeleting";
static NSString * const kSGNSkyglowEmptyFooter = @"Applications that have registered with Skyglow Notifications will appear here.";
static NSString * const kSGNAPNsEmptyFooter = @"Applications that have registered with Apple Push Notifications will appear here.";
static NSString * const kSGNSkyglowPopulatedFooter = @"Toggle to mute Skyglow notifications for an app. Swipe to forget, the app will prompt you for a provider next time it asks for notifications.";
static NSString * const kSGNAPNsPopulatedFooter = @"These apps were registered with Apple Push for notifications. Swipe to forget, the app will prompt you for a provider next time it opens.";

@interface SNAppListController () <UIAlertViewDelegate>
@property (nonatomic, strong) NSArray *apsdBundles;
@property (nonatomic, assign) BOOL apsdLoadFailed;
@property (nonatomic, strong) NSString *apsdLoadErrorMessage;
@property (nonatomic, strong) NSMutableSet *deletingBundleIDs;
@property (nonatomic, strong) NSMutableSet *pendingDeletionBundleIDs;
@property (nonatomic, strong) PSSpecifier *failedDeletionSpecifier;
@property (nonatomic, strong) NSIndexPath *failedDeletionIndexPath;
@property (nonatomic, strong) NSString *failedDeletionBundleId;
@end

@implementation SNAppListController

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self _refreshAPNsList];
}

- (void)_refreshAPNsList {
    [SNChannelGateway queryNativelyPushRegisteredBundlesWithCompletion:^(BOOL ok, NSArray *bundleIds, NSString *message) {
        if (!ok) {
            self.apsdLoadFailed = YES;
            self.apsdLoadErrorMessage = message ?: @"Could not communicate with SpringBoard. Try again after respringing.";
            self.apsdBundles = @[];
            [self reloadSpecifiers];
            return;
        }

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

        if (!self.apsdLoadFailed && self.apsdBundles && [self.apsdBundles isEqualToArray:sorted]) return;
        self.apsdLoadFailed = NO;
        self.apsdLoadErrorMessage = nil;
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
        if ([self.deletingBundleIDs containsObject:bundleId]) {
            [spec setProperty:@YES forKey:kSGNDeletingPropKey];
        }
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

    if (self.apsdLoadFailed) {
        [groupSpec setProperty:self.apsdLoadErrorMessage ?: @"No registered applications."
                        forKey:@"footerText"];
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
        if ([self.deletingBundleIDs containsObject:bundleId]) {
            [spec setProperty:@YES forKey:kSGNDeletingPropKey];
        }
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

- (NSMutableSet *)deletingBundleIDs {
    if (!_deletingBundleIDs) _deletingBundleIDs = [NSMutableSet set];
    return _deletingBundleIDs;
}

- (NSMutableSet *)pendingDeletionBundleIDs {
    if (!_pendingDeletionBundleIDs) _pendingDeletionBundleIDs = [NSMutableSet set];
    return _pendingDeletionBundleIDs;
}

- (BOOL)_isDeleting {
    return [self.deletingBundleIDs count] > 0;
}

- (BOOL)_hasDeleteRequestInFlight {
    return ([self.deletingBundleIDs count] > 0 || [self.pendingDeletionBundleIDs count] > 0);
}

- (void)_setBackButtonDisabledForDeletingState {
    self.navigationItem.hidesBackButton = [self _isDeleting];
}

- (void)_setSpecifier:(PSSpecifier *)specifier deleting:(BOOL)deleting bundleId:(NSString *)bundleId {
    if (deleting) {
        if (bundleId.length) [self.deletingBundleIDs addObject:bundleId];
    } else if (bundleId.length) {
        [self.deletingBundleIDs removeObject:bundleId];
    }
    [specifier setProperty:@(deleting) forKey:kSGNDeletingPropKey];
    [self _setBackButtonDisabledForDeletingState];
}

- (void)_setVisibleCellAtIndexPath:(NSIndexPath *)indexPath deleting:(BOOL)deleting {
    SNAppToggleCell *cell = (SNAppToggleCell *)[self.table cellForRowAtIndexPath:indexPath];
    if ([cell isKindOfClass:[SNAppToggleCell class]]) {
        [cell setDeletingAccessoryVisible:deleting];
    }
}

- (void)_scheduleVisibleSpinnerForSpecifier:(PSSpecifier *)specifier
                                  indexPath:(NSIndexPath *)indexPath
                                   bundleId:(NSString *)bundleId {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (![self.pendingDeletionBundleIDs containsObject:bundleId]) return;
        [self.pendingDeletionBundleIDs removeObject:bundleId];
        [self _setSpecifier:specifier deleting:YES bundleId:bundleId];
        [self _setVisibleCellAtIndexPath:indexPath deleting:YES];
    });
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
                               delegate:self
                      cancelButtonTitle:@"OK"
                      otherButtonTitles:nil] show];
}

- (void)_clearFailedDeletionState {
    PSSpecifier *specifier = self.failedDeletionSpecifier;
    NSIndexPath *indexPath = self.failedDeletionIndexPath;
    NSString *bundleId = self.failedDeletionBundleId;

    self.failedDeletionSpecifier = nil;
    self.failedDeletionIndexPath = nil;
    self.failedDeletionBundleId = nil;

    if (!bundleId.length || !specifier) return;
    [self.pendingDeletionBundleIDs removeObject:bundleId];
    [self _setSpecifier:specifier deleting:NO bundleId:bundleId];
    if (indexPath) [self _setVisibleCellAtIndexPath:indexPath deleting:NO];
}

- (void)alertView:(UIAlertView *)alertView didDismissWithButtonIndex:(NSInteger)buttonIndex {
    [self _clearFailedDeletionState];
}

- (UITableViewCellEditingStyle)tableView:(UITableView *)tableView editingStyleForRowAtIndexPath:(NSIndexPath *)indexPath {
    if ([self _isDeleting]) return UITableViewCellEditingStyleNone;
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
    if ([[specifier propertyForKey:kSGNDeletingPropKey] boolValue]) return;
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
    if ([self _isDeleting]) return NO;
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
    if ([self _hasDeleteRequestInFlight]) return;

    NSString *section = [spec propertyForKey:kSGNSectionPropKey];
    [tableView setEditing:NO animated:YES];
    [self.pendingDeletionBundleIDs addObject:bundleId];
    [self _scheduleVisibleSpinnerForSpecifier:spec indexPath:indexPath bundleId:bundleId];

    [SNChannelGateway deleteAppForBundleId:bundleId completion:^(BOOL ok, NSString *message) {
        [self.pendingDeletionBundleIDs removeObject:bundleId];
        if (!ok) {
            self.failedDeletionSpecifier = spec;
            self.failedDeletionIndexPath = indexPath;
            self.failedDeletionBundleId = bundleId;
            [self _showDeletionErrorForBundleId:bundleId message:message];
            return;
        }

        if ([section isEqualToString:kSGNSectionSkyglow]) {
            [[SNDataManager shared] removeAppStatusForBundleId:bundleId];
        }
        [self _removeBundleSpecifier:spec section:section bundleId:bundleId];
        [self _setSpecifier:spec deleting:NO bundleId:bundleId];
    }];
}

@end
