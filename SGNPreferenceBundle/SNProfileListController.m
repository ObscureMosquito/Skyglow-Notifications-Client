#import "SNProfileListController.h"
#import "SNServerInfoViewController.h"
#import "SNDataManager.h"
#import <CoreFoundation/CoreFoundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

static void SNPostReloadConfig(void) {
    CFNotificationCenterPostNotificationWithOptions(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFSTR("com.skyglow.sgn.reload_config"),
        NULL, NULL, kCFNotificationDeliverImmediately);
}

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
    detailFrame.origin.y -= 2.0f;   // move detail text upward
    self.detailTextLabel.frame = detailFrame;
}

@end

@implementation SNProfileListController {
    NSMutableArray *_profileIndices;   /* e.g. @[@1, @3, @5] — existing profiles */
}

- (id)init {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        self.title = @"Server Profiles";
        _profileIndices = [[NSMutableArray alloc] init];
    }
    return self;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self _reloadProfileIndices];
    [self.tableView reloadData];
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
            cell = [[ProfileCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                    reuseIdentifier:@"ProfileCell"];
        }

        NSInteger idx = [[_profileIndices objectAtIndex:indexPath.row] integerValue];
        SNDataManager *dm = [SNDataManager shared];
        NSDictionary *profile = [dm profileForIndex:idx];
        NSString *addr = [profile objectForKey:@"server_address"];
        BOOL isActive = ([dm activeProfileIndex] == idx);

        cell.textLabel.text       = [NSString stringWithFormat:@"Profile %ld", (long)idx];
        cell.detailTextLabel.text = (addr && [addr length] > 0) ? addr : @"Not Configured";
        cell.detailTextLabel.textColor = [UIColor grayColor];
        cell.accessoryType = isActive ? UITableViewCellAccessoryCheckmark
                                      : UITableViewCellAccessoryDisclosureIndicator;
        cell.selectionStyle = UITableViewCellSelectionStyleBlue;
        return cell;
    }

    /* SectionAdd */
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"AddCell"];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                      reuseIdentifier:@"AddCell"];
    }
    cell.textLabel.text      = @"Add Profile";
    cell.textLabel.textColor = [UIColor colorWithRed:0.05f green:0.42f blue:0.86f alpha:1.0f];
    cell.accessoryType       = UITableViewCellAccessoryDisclosureIndicator;
    cell.selectionStyle      = UITableViewCellSelectionStyleBlue;
    return cell;
}

#pragma mark - UITableViewDelegate

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];

    if (indexPath.section == SectionAdd) {
        /* Find the lowest unused index 1-5 */
        NSInteger newIdx = 0;
        for (NSInteger i = 1; i <= 5; i++) {
            if (![[SNDataManager shared] profileExistsAtIndex:i]) {
                newIdx = i;
                break;
            }
        }
        if (newIdx == 0) return; /* shouldn't happen — row is hidden when full */

        SNServerInfoViewController *vc = [[SNServerInfoViewController alloc] initWithProfileIndex:newIdx];
        [self.navigationController pushViewController:vc animated:YES];
        return;
    }

    /* SectionProfiles — tap a profile row */
    NSInteger idx = [[_profileIndices objectAtIndex:indexPath.row] integerValue];
    SNDataManager *dm = [SNDataManager shared];
    BOOL isActive = ([dm activeProfileIndex] == idx);

    if (isActive) {
        /* Already active — go straight to detail */
        SNServerInfoViewController *vc = [[SNServerInfoViewController alloc] initWithProfileIndex:idx];
        [self.navigationController pushViewController:vc animated:YES];
    } else {
        /* Non-active profile — show action sheet with Set Active + View */
        [self _showActionSheetForProfileIndex:idx];
    }
}

#pragma mark - Swipe to delete

- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath {
    return (indexPath.section == SectionProfiles);
}

- (void)tableView:(UITableView *)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle forRowAtIndexPath:(NSIndexPath *)indexPath {
    if (editingStyle != UITableViewCellEditingStyleDelete) return;

    NSInteger idx = [[_profileIndices objectAtIndex:indexPath.row] integerValue];
    SNDataManager *dm = [SNDataManager shared];

    [dm deleteProfileAtIndex:idx];

    /* If we deleted the active profile, pick the next available one */
    if ([dm activeProfileIndex] == idx) {
        NSInteger nextActive = 0;
        for (NSInteger i = 1; i <= 5; i++) {
            if (i != idx && [dm profileExistsAtIndex:i]) {
                nextActive = i;
                break;
            }
        }
        if (nextActive > 0) {
            [dm setActiveProfileIndex:nextActive];
        } else {
            /* No profiles left — disable daemon */
            [dm setMainPrefValue:@NO forKey:@"enabled"];
        }
        SNPostReloadConfig();
    }

    [_profileIndices removeObjectAtIndex:indexPath.row];

    /* Reload the whole table — mixing deleteRows + reloadSections on
       overlapping sections triggers UITableView internal-consistency
       assertions.  A plain reloadData is safe and keeps footer text,
       Add-row visibility, and checkmark state all in sync. */
    [tableView reloadData];
}

#pragma mark - Action sheet for non-active profile

- (void)_showActionSheetForProfileIndex:(NSInteger)idx {
    Class alertControllerClass = NSClassFromString(@"UIAlertController");
    if (alertControllerClass) {
        SEL createSel = NSSelectorFromString(@"alertControllerWithTitle:message:preferredStyle:");
        id (*create)(Class, SEL, id, id, NSInteger) =
            (id (*)(Class, SEL, id, id, NSInteger))objc_msgSend;
        id sheet = create(alertControllerClass, createSel,
                          [NSString stringWithFormat:@"Profile %ld", (long)idx],
                          nil, 0 /* ActionSheet */);

        Class actionClass = NSClassFromString(@"UIAlertAction");
        SEL actionSel = NSSelectorFromString(@"actionWithTitle:style:handler:");
        id (*makeAction)(Class, SEL, id, NSInteger, id) =
            (id (*)(Class, SEL, id, NSInteger, id))objc_msgSend;

        __weak typeof(self) weakSelf = self;
        NSInteger capturedIdx = idx;

        id setActiveAction = makeAction(actionClass, actionSel, @"Set Active", 0,
            ^(id action) {
                [[SNDataManager shared] setActiveProfileIndex:capturedIdx];
                SNPostReloadConfig();
                [weakSelf.tableView reloadData];
            });

        id viewAction = makeAction(actionClass, actionSel, @"View Details", 0,
            ^(id action) {
                SNServerInfoViewController *vc =
                    [[SNServerInfoViewController alloc] initWithProfileIndex:capturedIdx];
                [weakSelf.navigationController pushViewController:vc animated:YES];
            });

        id cancelAction = makeAction(actionClass, actionSel, @"Cancel", 1, nil);

        SEL addSel = NSSelectorFromString(@"addAction:");
        void (*addAction)(id, SEL, id) = (void (*)(id, SEL, id))objc_msgSend;
        addAction(sheet, addSel, setActiveAction);
        addAction(sheet, addSel, viewAction);
        addAction(sheet, addSel, cancelAction);

        SEL presentSel = NSSelectorFromString(@"presentViewController:animated:completion:");
        void (*present)(id, SEL, id, BOOL, id) = (void (*)(id, SEL, id, BOOL, id))objc_msgSend;
        present(self, presentSel, sheet, YES, nil);
    } else {
        /* iOS 6 — UIActionSheet */
        UIActionSheet *as = [[UIActionSheet alloc]
                             initWithTitle:[NSString stringWithFormat:@"Profile %ld", (long)idx]
                                  delegate:(id<UIActionSheetDelegate>)self
                         cancelButtonTitle:@"Cancel"
                    destructiveButtonTitle:nil
                         otherButtonTitles:@"Set Active", @"View Details", nil];
        as.tag = idx;
        [as showInView:self.view];
    }
}

/* UIActionSheetDelegate (iOS 6) */
- (void)actionSheet:(UIActionSheet *)actionSheet clickedButtonAtIndex:(NSInteger)buttonIndex {
    NSInteger idx = actionSheet.tag;
    if (buttonIndex == 0) {
        /* Set Active */
        [[SNDataManager shared] setActiveProfileIndex:idx];
        SNPostReloadConfig();
        [self.tableView reloadData];
    } else if (buttonIndex == 1) {
        /* View Details */
        SNServerInfoViewController *vc =
            [[SNServerInfoViewController alloc] initWithProfileIndex:idx];
        [self.navigationController pushViewController:vc animated:YES];
    }
}

@end
