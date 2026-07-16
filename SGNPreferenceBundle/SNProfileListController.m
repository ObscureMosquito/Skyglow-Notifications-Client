#import "SNProfileListController.h"
#import "SNInterfaceColors.h"
#import "SNServerInfoViewController.h"
#import "SNDataManager.h"
#import "SNChannelGateway.h"
#import "SNDeferredActivity.h"
#import <CoreFoundation/CoreFoundation.h>
#import <QuartzCore/QuartzCore.h>
#import "SNAlert.h"

enum {
    SectionProfiles = 0,
    SectionAdd      = 1,
    SectionTotal    = 2
};

@interface ProfileCell : UITableViewCell
@end

@implementation ProfileCell

- (void)layoutSubviews {
    [super layoutSubviews];

    CGRect detailFrame = self.detailTextLabel.frame;
    detailFrame.origin.y -= 2.0f;
    self.detailTextLabel.frame = detailFrame;
}

@end

@implementation SNProfileListController {
    NSMutableArray *_profileIndices;
    NSMutableSet   *_pendingDeletionIndices;  /* delete: in-flight (pre-spinner grace) */
    NSMutableSet   *_deletingIndices;         /* delete: visible spinner */
    SNDeferredActivity *_deleteActivity;
    NSNumber       *_activatingIndex;         /* set-active: in-flight (visible spinner) */
    SNDeferredActivity *_activateActivity;
}

- (BOOL)_isBusy {
    return (_deletingIndices.count > 0 ||
            _pendingDeletionIndices.count > 0 ||
            _activatingIndex != nil);
}
- (void)_setBackButtonHiddenForBusyState {
    self.navigationItem.hidesBackButton = [self _isBusy];
}

/* iOS 4-5 PSRootController calls these on every pushed VC during the
 * back-pop sequence, even on plain UIViewControllers.  Crashes with
 * "unrecognized selector" otherwise. */
- (void)setRootController:(id)controller   {}
- (void)setParentController:(id)controller {}
- (void)setSpecifier:(id)specifier         {}
- (void)willResignActive                   {}
- (void)willBecomeActive                   {}

- (id)init {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        self.title = @"Server Profiles";
        _profileIndices         = [[NSMutableArray alloc] init];
        _pendingDeletionIndices = [[NSMutableSet alloc] init];
        _deletingIndices        = [[NSMutableSet alloc] init];
    }
    return self;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self _reloadProfileIndices];
    [self.tableView reloadData];
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(_daemonStatusUpdated:)
                                                 name:@"SNDaemonStatusUpdated"
                                               object:nil];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    [[NSNotificationCenter defaultCenter] removeObserver:self
                                                    name:@"SNDaemonStatusUpdated"
                                                  object:nil];
}

- (void)_daemonStatusUpdated:(NSNotification *)note {
    [self.tableView reloadData];
}

- (BOOL)_activeProfileHasError {
    uint32_t state = [SNDataManager shared].latestPayload.state;
    return (state == SGStateErrorAuth ||
            state == SGStateErrorBadConfig ||
            state == SGStateErrorVersionMismatch);
}

- (void)_reloadProfileIndices {
    [_profileIndices removeAllObjects];
    SNDataManager *dm = [SNDataManager shared];
    for (NSInteger i = 1; i <= 5; i++) {
        if ([dm profileExistsAtIndex:i]) {
            [_profileIndices addObject:@(i)];
        }
    }
}

#pragma mark - Edit mode

- (void)viewDidLoad {
    [super viewDidLoad];
    self.navigationItem.rightBarButtonItem = [self editButtonItem];
}

#pragma mark - UITableViewDataSource

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return SectionTotal;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (section == SectionProfiles) return (NSInteger)[_profileIndices count];
    if (section == SectionAdd)     return ([_profileIndices count] < 5) ? 1 : 0;
    return 0;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (section == SectionProfiles && [_profileIndices count] > 0) return @"Profiles";
    return nil;
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == SectionProfiles && [_profileIndices count] == 0)
        return @"No profiles configured. Tap \"Add Profile\" to get started.";
    if (section == SectionAdd && [_profileIndices count] >= 5)
        return @"Maximum of 5 profiles reached.";
    return nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {

    if (indexPath.section == SectionProfiles) {
        ProfileCell *cell = (ProfileCell *)[tableView dequeueReusableCellWithIdentifier:@"ProfileCell"];
        if (!cell) {
            cell = [[[ProfileCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                    reuseIdentifier:@"ProfileCell"] autorelease];
        }

        NSInteger idx = [[_profileIndices objectAtIndex:indexPath.row] integerValue];
        SNDataManager *dm = [SNDataManager shared];
        NSDictionary *profile = [dm profileForIndex:idx];
        NSString *addr = [profile objectForKey:@"server_address"];
        BOOL isActive = ([dm activeProfileIndex] == idx);

        cell.textLabel.text       = [NSString stringWithFormat:@"Profile %ld", (long)idx];
        cell.detailTextLabel.text = (addr && [addr length] > 0) ? addr : @"Not Configured";
        cell.detailTextLabel.textColor = SNSecondaryLabelColor([UIColor grayColor]);

        BOOL showSpinner = [_deletingIndices containsObject:@(idx)] ||
                           (_activatingIndex && [_activatingIndex integerValue] == idx);
        if (showSpinner) {
            UIActivityIndicatorView *spin = [[UIActivityIndicatorView alloc]
                initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
            [spin startAnimating];
            cell.accessoryView = spin;
            [spin release];
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
        } else if ((isActive && [self _activeProfileHasError]) ||
                   [dm registrationStatusForProfileAtIndex:idx] == SNRegistrationNeedsCertificate) {
            UILabel *warning = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, 22.0f, 22.0f)];
            warning.text            = @"!";
            warning.font            = [UIFont boldSystemFontOfSize:15.0f];
            warning.textAlignment   = NSTextAlignmentCenter;
            warning.textColor       = [UIColor whiteColor];
            warning.backgroundColor = SNSystemRedColor([UIColor redColor]);
            warning.layer.cornerRadius  = 11.0f;
            warning.layer.masksToBounds = YES;
            cell.accessoryView  = warning;
            cell.accessoryType  = UITableViewCellAccessoryNone;
            [warning release];
            cell.selectionStyle = UITableViewCellSelectionStyleBlue;
        } else {
            cell.accessoryView = nil;
            cell.accessoryType = isActive ? UITableViewCellAccessoryCheckmark
                                          : UITableViewCellAccessoryDisclosureIndicator;
            cell.selectionStyle = UITableViewCellSelectionStyleBlue;
        }
        return cell;
    }

    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"AddCell"];
    if (!cell) {
        cell = [[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                      reuseIdentifier:@"AddCell"] autorelease];
    }
    cell.textLabel.text      = @"Add Profile";
    cell.textLabel.textColor = SNSystemBlueColor([UIColor colorWithRed:0.05f green:0.42f blue:0.86f alpha:1.0f]);
    cell.accessoryType       = UITableViewCellAccessoryDisclosureIndicator;
    cell.selectionStyle      = UITableViewCellSelectionStyleBlue;
    return cell;
}

#pragma mark - UITableViewDelegate

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];

    if ([self _isBusy]) return;

    if (indexPath.section == SectionAdd) {
        NSInteger newIdx = 0;
        for (NSInteger i = 1; i <= 5; i++) {
            if (![[SNDataManager shared] profileExistsAtIndex:i]) {
                newIdx = i;
                break;
            }
        }
        if (newIdx == 0) return;

        SNServerInfoViewController *vc = [[SNServerInfoViewController alloc] initWithProfileIndex:newIdx];
        [self.navigationController pushViewController:vc animated:YES];
        [vc release];
        return;
    }

    NSInteger idx = [[_profileIndices objectAtIndex:indexPath.row] integerValue];
    SNDataManager *dm = [SNDataManager shared];
    BOOL isActive = ([dm activeProfileIndex] == idx);

    if (isActive) {
        SNServerInfoViewController *vc = [[SNServerInfoViewController alloc] initWithProfileIndex:idx];
        [self.navigationController pushViewController:vc animated:YES];
        [vc release];
    } else {
        [self _showActionSheetForProfileIndex:idx fromView:[tableView cellForRowAtIndexPath:indexPath]];
    }
}

#pragma mark - Set Active flow

- (void)_performSetActiveForIndex:(NSInteger)idx {
    if ([self _isBusy]) return;

    NSNumber *idxKey = [[NSNumber alloc] initWithInteger:idx];
    [_activatingIndex release];
    _activatingIndex = idxKey;   /* transfer ownership */
    [self _setBackButtonHiddenForBusyState];

    [_activateActivity release];
    _activateActivity = [[SNDeferredActivity alloc] initWithShowBlock:^{
        if (!_activatingIndex || [_activatingIndex integerValue] != idx) return;
        [self.tableView reloadData];
    } hideBlock:^{

    }];
    [_activateActivity begin];

    [SNChannelGateway setActiveProfileAtIndex:idx
                                   completion:^(BOOL ok, NSString *message) {
        SNDeferredActivity *activity = [_activateActivity retain];
        [activity finishWithCompletion:^{
            [_activatingIndex release];
            _activatingIndex = nil;
            [_activateActivity release];
            _activateActivity = nil;
            [self _setBackButtonHiddenForBusyState];

            if (!ok) {
                [SNAlert presentMessage:message ?: @"The daemon did not respond."
                                  title:@"Could Not Switch Profile"
                                   from:self];
                [self.tableView reloadData];
                return;
            }
            [self.tableView reloadData];
        }];
        [activity release];
    }];
}

#pragma mark - Swipe to delete

- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath {
    if ([self _isBusy]) return NO;
    return (indexPath.section == SectionProfiles);
}

- (UITableViewCellEditingStyle)tableView:(UITableView *)tableView editingStyleForRowAtIndexPath:(NSIndexPath *)indexPath {
    if ([self _isBusy]) return UITableViewCellEditingStyleNone;
    if (indexPath.section != SectionProfiles) return UITableViewCellEditingStyleNone;
    return UITableViewCellEditingStyleDelete;
}

- (void)tableView:(UITableView *)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle forRowAtIndexPath:(NSIndexPath *)indexPath {
    if (editingStyle != UITableViewCellEditingStyleDelete) return;
    if (indexPath.row >= (NSInteger)_profileIndices.count) return;
    if ([self _isBusy]) return;

    NSInteger idx = [[_profileIndices objectAtIndex:indexPath.row] integerValue];
    NSNumber *idxKey = [NSNumber numberWithInteger:idx];
    NSIndexPath *capturedPath = [[indexPath copy] autorelease];

    [tableView setEditing:NO animated:YES];
    [_pendingDeletionIndices addObject:idxKey];
    [self _setBackButtonHiddenForBusyState];

    [_deleteActivity release];
    _deleteActivity = [[SNDeferredActivity alloc] initWithShowBlock:^{
        if (![_pendingDeletionIndices containsObject:idxKey]) return;
        [_pendingDeletionIndices removeObject:idxKey];
        [_deletingIndices addObject:idxKey];
        [self _setBackButtonHiddenForBusyState];
        if (capturedPath.row < (NSInteger)_profileIndices.count &&
            [[_profileIndices objectAtIndex:capturedPath.row] integerValue] == idx) {
            [self.tableView reloadRowsAtIndexPaths:@[capturedPath]
                                  withRowAnimation:UITableViewRowAnimationNone];
        }
    } hideBlock:^{
        [_deletingIndices removeObject:idxKey];
        if (capturedPath.row < (NSInteger)_profileIndices.count) {
            [self.tableView reloadRowsAtIndexPaths:@[capturedPath]
                                  withRowAnimation:UITableViewRowAnimationNone];
        }
    }];
    [_deleteActivity begin];

    [SNChannelGateway deleteProfileAtIndex:idx
                                completion:^(BOOL ok, NSString *message) {
        SNDeferredActivity *activity = [_deleteActivity retain];
        [activity finishWithCompletion:^{
            [_pendingDeletionIndices removeObject:idxKey];
            [_deletingIndices removeObject:idxKey];
            [_deleteActivity release];
            _deleteActivity = nil;
            [self _setBackButtonHiddenForBusyState];

            if (!ok) {
                [SNAlert presentMessage:message ?: @"The daemon did not respond. Try again."
                                  title:@"Could Not Delete Profile"
                                   from:self];
                if (capturedPath.row < (NSInteger)_profileIndices.count) {
                    [self.tableView reloadRowsAtIndexPaths:@[capturedPath]
                                          withRowAnimation:UITableViewRowAnimationNone];
                }
                return;
            }

            [self _reloadProfileIndices];
            [self.tableView reloadData];
        }];
        [activity release];
    }];
}

#pragma mark - Action sheet for non-active profile

- (void)_showActionSheetForProfileIndex:(NSInteger)idx fromView:(UIView *)sourceView {
    NSInteger capturedIdx = idx;
    [SNAlert presentActionSheetTitle:[NSString stringWithFormat:@"Profile %ld", (long)idx]
                        cancelButton:@"Cancel"
                   destructiveButton:nil
                        otherButtons:@[@"Set Active", @"View Details"]
                                from:self
                          sourceView:sourceView
                            onSelect:^(NSString *buttonTitle) {
        if ([buttonTitle isEqualToString:@"Set Active"]) {
            [self _performSetActiveForIndex:capturedIdx];
        } else if ([buttonTitle isEqualToString:@"View Details"]) {
            SNServerInfoViewController *vc =
                [[SNServerInfoViewController alloc] initWithProfileIndex:capturedIdx];
            [self.navigationController pushViewController:vc animated:YES];
            [vc release];
        }
    }];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [_profileIndices release];
    [_pendingDeletionIndices release];
    [_deletingIndices release];
    [_deleteActivity release];
    [_activatingIndex release];
    [_activateActivity release];
    [super dealloc];
}

@end
