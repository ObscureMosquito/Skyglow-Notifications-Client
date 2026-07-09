#import "SNAppListController.h"
#import "SNDataManager.h"
#import "SNChannelGateway.h"
#import "SNDeferredActivity.h"
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

@interface SNAppListController ()
@property (nonatomic, strong) NSArray *apsdBundles;
@property (nonatomic, assign) BOOL apsdLoadFailed;
@property (nonatomic, strong) NSString *apsdLoadErrorMessage;
@property (nonatomic, strong) NSMutableSet *deletingBundleIDs;
@property (nonatomic, strong) NSMutableSet *pendingDeletionBundleIDs;
@property (nonatomic, strong) SNDeferredActivity *deleteActivity;
@end

@implementation SNAppListController

- (void)dealloc {
    [_apsdBundles release];
    [_apsdLoadErrorMessage release];
    [_deletingBundleIDs release];
    [_pendingDeletionBundleIDs release];
    [_deleteActivity release];
    [super dealloc];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self reloadSpecifiers];
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
        for (id bid in bundleIds) {
            if (![bid isKindOfClass:[NSString class]] || [bid length] == 0) continue;
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
    NSMutableArray *specs = [[NSMutableArray alloc] init];
    [self _buildSkyglowSectionInto:specs];
    [self _buildAPNsSectionInto:specs];
    [_specifiers release];
    _specifiers = specs;
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
        [spec setProperty:@YES forKey:@"sgnHideToggle"];
        [spec setProperty:kSGNSectionAPNs forKey:kSGNSectionPropKey];
        if ([self.deletingBundleIDs containsObject:bundleId]) {
            [spec setProperty:@YES forKey:kSGNDeletingPropKey];
        }
        [specs addObject:spec];
    }
}

- (NSMutableSet *)deletingBundleIDs {
    if (!_deletingBundleIDs) _deletingBundleIDs = [[NSMutableSet alloc] init];
    return _deletingBundleIDs;
}

- (NSMutableSet *)pendingDeletionBundleIDs {
    if (!_pendingDeletionBundleIDs) _pendingDeletionBundleIDs = [[NSMutableSet alloc] init];
    return _pendingDeletionBundleIDs;
}

- (BOOL)_isDeleting {
    return [self.deletingBundleIDs count] > 0;
}

- (BOOL)_hasDeleteRequestInFlight {
    return ([self.deletingBundleIDs count] > 0 || [self.pendingDeletionBundleIDs count] > 0);
}

- (void)_backButtonHideForDelete {
    [self.navigationItem setHidesBackButton:YES animated:NO];
}
- (void)_backButtonRestoreAfterDelete {
    [self.navigationItem setHidesBackButton:NO animated:NO];
}

- (void)_setBackButtonDisabledForDeletingState {
    [self.navigationItem setHidesBackButton:[self _hasDeleteRequestInFlight] animated:NO];
}

- (void)_setSpecifier:(PSSpecifier *)specifier deleting:(BOOL)deleting bundleId:(NSString *)bundleId {
    if (deleting) {
        if (bundleId.length) [self.deletingBundleIDs addObject:bundleId];
    } else if (bundleId.length) {
        [self.deletingBundleIDs removeObject:bundleId];
    }
    [specifier setProperty:@(deleting) forKey:kSGNDeletingPropKey];
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
    PSSpecifier *specRet  = [specifier retain];
    NSIndexPath *pathCopy = [indexPath copy];
    NSString    *bidCopy  = [bundleId copy];

    self.deleteActivity = [[[SNDeferredActivity alloc] initWithShowBlock:^{
        if (![self.pendingDeletionBundleIDs containsObject:bidCopy]) return;
        [self.pendingDeletionBundleIDs removeObject:bidCopy];
        [self _setSpecifier:specRet deleting:YES bundleId:bidCopy];
        [self _setVisibleCellAtIndexPath:pathCopy deleting:YES];
        [self _backButtonHideForDelete];
    } hideBlock:^{
        [self _setSpecifier:specRet deleting:NO bundleId:bidCopy];
        [self _setVisibleCellAtIndexPath:pathCopy deleting:NO];
        [specRet release];
        [pathCopy release];
        [bidCopy release];
    }] autorelease];
    [self.deleteActivity begin];
}

- (void)_removeAPNsBundleFromCachedList:(NSString *)bundleId {
    if (!bundleId.length || self.apsdBundles.count == 0) return;
    NSMutableArray *next = [NSMutableArray arrayWithArray:self.apsdBundles];
    [next removeObject:bundleId];
    self.apsdBundles = next;
}

- (void)_showDeletionErrorForBundleId:(NSString *)bundleId message:(NSString *)message {
    NSString *title = @"Could Not Forget App";
    NSString *body = message.length ? message : @"Could not communicate with SpringBoard. Try again after respringing.";
    if (bundleId.length) {
        body = [NSString stringWithFormat:@"%@\n\n%@", bundleId, body];
    }

    UIAlertView *av = [[UIAlertView alloc] initWithTitle:title
                                                 message:body
                                                delegate:nil
                                       cancelButtonTitle:@"OK"
                                       otherButtonTitles:nil];
    [av show];
    [av release];
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

    /* The daemon now owns the appStatus plist write (via ENABLE/DISABLE_APP), so
     * the UI no longer writes it here.  The switch keeps the position the user
     * set it to; on daemon failure we reload the specifier, which re-reads the
     * unchanged daemon state and thereby reverts the switch. */
    PSSpecifier *specRet = [specifier retain];
    SNChannelCommandCompletion done = ^(BOOL ok, NSString *message) {
        if (!ok) [self reloadSpecifier:specRet animated:YES];
        [specRet release];
    };
    if (on) {
        [SNChannelGateway enableAppForBundleId:bundleId completion:done];
    } else {
        [SNChannelGateway disableAppForBundleId:bundleId completion:done];
    }
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

    PSSpecifier *specRet  = [spec retain];
    NSIndexPath *pathCopy = [indexPath copy];
    NSString    *bidCopy  = [bundleId copy];
    NSString    *secCopy  = [section copy];

    [SNChannelGateway deleteAppForBundleId:bidCopy completion:^(BOOL ok, NSString *message) {
        SNDeferredActivity *activity = [self.deleteActivity retain];
        [activity finishWithCompletion:^{
            [self.pendingDeletionBundleIDs removeObject:bidCopy];
            self.deleteActivity = nil;
            [self _backButtonRestoreAfterDelete];

            if (!ok) {
                [self _showDeletionErrorForBundleId:bidCopy message:message];
            } else {
                if ([secCopy isEqualToString:kSGNSectionSkyglow]) {
                    /* appStatus removal is now part of the daemon's DELETE_APP
                     * cascade — no client-side plist write. */
                } else if ([secCopy isEqualToString:kSGNSectionAPNs]) {
                    [self _removeAPNsBundleFromCachedList:bidCopy];
                }
                [self _setSpecifier:specRet deleting:NO bundleId:bidCopy];
                [self reloadSpecifiers];
            }

            [specRet release];
            [pathCopy release];
            [bidCopy release];
            [secCopy release];
        }];
        [activity release];
    }];
}

@end
