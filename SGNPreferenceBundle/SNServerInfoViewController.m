#import "SNServerInfoViewController.h"
#import "SNDataManager.h"
#import "SFPFilePicker/include/SFPFilePicker.h"
#import <CoreFoundation/CoreFoundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

static void SNPostReloadConfig(void) {
    CFNotificationCenterPostNotificationWithOptions(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFSTR("com.skyglow.sgn.reload_config"),
        NULL, NULL, kCFNotificationDeliverImmediately);
}

typedef enum {
    WizardSectionServer = 0,
    WizardSectionCert   = 1,
    WizardSectionCount  = 2
} WizardSection;

typedef enum {
    SectionServer  = 0,
    SectionDevice  = 1,
    SectionActions = 2,
    SectionCount   = 3
} ServerInfoSection;

static const NSInteger kAlertTagPEMConfirm  = 1;
static const NSInteger kAlertTagUnregister  = 2;


@interface SNServerInfoViewController () <UIAlertViewDelegate, UITextFieldDelegate, SFPFilePickerDelegate>

@property (nonatomic, strong) NSString    *pendingServerAddress;
@property (nonatomic, strong) NSString    *pendingPEMPath;
@property (nonatomic, weak)   UITextField *serverAddressField;
@property (nonatomic, weak)   UITextField *registeredAddressField;

@end

@implementation SNServerInfoViewController

- (id)init {
    return [self initWithProfileIndex:[[SNDataManager shared] activeProfileIndex]];
}

- (id)initWithProfileIndex:(NSInteger)index {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        _profileIndex = index;
        self.title = [NSString stringWithFormat:@"Profile %ld", (long)index];
    }
    return self;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self _updateTableHeaderView];
    [self.tableView reloadData];
}

- (void)_updateTableHeaderView {
    if (![self isRegistered]) {
        CGFloat w = self.tableView.bounds.size.width;
        if (w < 10.0f) w = 320.0f;

        CGFloat iconSize      = 62.0f;
        CGFloat smallIconSize = 55.5f;
        CGFloat arrowWidth    = 30.0f;
        CGFloat spacing       = 16.0f;
        CGFloat topPad        = 22.0f;
        CGFloat totalGroupWidth = iconSize + spacing + arrowWidth + spacing + smallIconSize;
        CGFloat startX = (w - totalGroupWidth) / 2.0f;

        NSBundle *bundle = [NSBundle bundleForClass:[self class]];

        UIImage *webIcon = [UIImage imageWithContentsOfFile:[bundle pathForResource:@"web" ofType:@"png"]];
        UIImageView *webIconView = [[UIImageView alloc] initWithImage:webIcon];
        webIconView.contentMode   = UIViewContentModeScaleAspectFit;
        webIconView.clipsToBounds = YES;
        webIconView.frame = CGRectMake(startX, topPad, iconSize, iconSize);

        UILabel *arrowLabel = [[UILabel alloc] initWithFrame:CGRectMake(startX + iconSize + spacing, topPad, arrowWidth, iconSize)];
        arrowLabel.text = @"➔";
        arrowLabel.font = [UIFont boldSystemFontOfSize:28.0f];
        arrowLabel.textColor = [UIColor colorWithRed:0.55f green:0.55f blue:0.58f alpha:1.0f];
        arrowLabel.shadowColor = [UIColor colorWithWhite:1.0f alpha:0.7f];
        arrowLabel.shadowOffset = CGSizeMake(0, 1);
        arrowLabel.backgroundColor = [UIColor clearColor];
        arrowLabel.textAlignment = NSTextAlignmentCenter;

        UIImage *settingsIcon = [UIImage imageWithContentsOfFile:[bundle pathForResource:@"icon-settings" ofType:@"png"]];
        UIImageView *settingsIconView = [[UIImageView alloc] initWithImage:settingsIcon];
        settingsIconView.contentMode   = UIViewContentModeScaleAspectFit;
        settingsIconView.clipsToBounds = YES;

        CGFloat settingsYOffset = topPad + ((iconSize - smallIconSize) / 2.0f);
        CGFloat settingsXOrigin = startX + iconSize + spacing + arrowWidth + spacing;

        settingsIconView.frame = CGRectMake(settingsXOrigin, settingsYOffset, smallIconSize, smallIconSize);

        CGFloat iconGap   = 10.0f;
        CGFloat titleGap  = 4.0f;
        CGFloat bodyGap   = 12.0f;
        CGFloat botPad    = 18.0f;
        CGFloat sideInset = 24.0f;

        UILabel *titleLabel     = [[UILabel alloc] init];
        titleLabel.text         = @"Skyglow Notifications";
        titleLabel.font         = [UIFont boldSystemFontOfSize:17.0f];
        titleLabel.textColor    = [UIColor colorWithRed:0.18f green:0.18f blue:0.18f alpha:1.0f];
        titleLabel.shadowColor  = [UIColor colorWithWhite:1.0f alpha:0.7f];
        titleLabel.shadowOffset = CGSizeMake(0, 1);
        titleLabel.textAlignment     = NSTextAlignmentCenter;
        titleLabel.backgroundColor   = [UIColor clearColor];
        CGFloat titleY = topPad + iconSize + iconGap;
        titleLabel.frame = CGRectMake(sideInset, titleY, w - sideInset * 2.0f, 22.0f);

        UILabel *bodyLabel      = [[UILabel alloc] init];
        bodyLabel.text          = @"Enter your server address below, then select\nyour server\xe2\x80\x99s public certificate to get started.";
        bodyLabel.font          = [UIFont systemFontOfSize:13.0f];
        bodyLabel.textColor     = [UIColor colorWithRed:0.38f green:0.38f blue:0.42f alpha:1.0f];
        bodyLabel.shadowColor   = [UIColor colorWithWhite:1.0f alpha:0.6f];
        bodyLabel.shadowOffset  = CGSizeMake(0, 1);
        bodyLabel.textAlignment    = NSTextAlignmentCenter;
        bodyLabel.backgroundColor  = [UIColor clearColor];
        bodyLabel.numberOfLines    = 0;
        CGFloat bodyY = titleY + 22.0f + titleGap;
        CGSize bodyFit = [bodyLabel sizeThatFits:CGSizeMake(w - sideInset * 2.0f, 999.0f)];
        bodyLabel.frame = CGRectMake(sideInset, bodyY, w - sideInset * 2.0f, bodyFit.height);

        CGFloat totalH = bodyY + bodyFit.height + bodyGap + botPad;
        UIView *header = [[UIView alloc] initWithFrame:CGRectMake(0, 0, w, totalH)];
        header.backgroundColor = [UIColor clearColor];
        
        [header addSubview:webIconView];
        [header addSubview:arrowLabel];
        [header addSubview:settingsIconView];
        
        [header addSubview:titleLabel];
        [header addSubview:bodyLabel];

        self.tableView.tableHeaderView = header;
    } else {
        self.tableView.tableHeaderView = nil;
    }
}

- (BOOL)isRegistered {
    NSDictionary *profile = [[SNDataManager shared] profileForIndex:self.profileIndex];
    NSString *addr = [profile objectForKey:@"server_address"];
    return (addr != nil && [addr length] > 0);
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return [self isRegistered] ? SectionCount : WizardSectionCount;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (![self isRegistered]) return 1;
    switch (section) {
        case SectionServer:  return 3;
        case SectionDevice:  return 1;
        case SectionActions: return 1;
        default: return 0;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (![self isRegistered]) {
        return (section == WizardSectionServer) ? @"Server Address" : @"Certificate";
    }
    switch (section) {
        case SectionServer: return @"Server Details";
        case SectionDevice: return @"Identity";
        default: return nil;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (![self isRegistered]) {
        if (section == WizardSectionServer)
            return @"Enter the hostname or IP address of your Skyglow notification server.";
        if (section == WizardSectionCert)
            return @"Select the server's public certificate (.pem). Enter the server address first.";
        return nil;
    }
    if (section == SectionActions)
        return @"Unregistering disables the daemon and deletes your cryptographic keys. App toggles are preserved.";
    return nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {

    if (![self isRegistered]) {

        if (indexPath.section == WizardSectionServer) {
            UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"TFCell"];
            if (!cell) {
                cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                              reuseIdentifier:@"TFCell"];
                cell.selectionStyle = UITableViewCellSelectionStyleNone;

                UITextField *tf = [[UITextField alloc] init];
                tf.placeholder              = @"hostname or IP address";
                tf.autocorrectionType       = UITextAutocorrectionTypeNo;
                tf.autocapitalizationType   = UITextAutocapitalizationTypeNone;
                tf.keyboardType             = UIKeyboardTypeURL;
                tf.returnKeyType            = UIReturnKeyDone;
                tf.clearButtonMode          = UITextFieldViewModeWhileEditing;
                tf.delegate                 = self;
                tf.font                     = [UIFont systemFontOfSize:15.0f];
                tf.contentVerticalAlignment = UIControlContentVerticalAlignmentCenter;
                tf.autoresizingMask         = UIViewAutoresizingFlexibleWidth;
                tf.tag                      = 100;
                [cell.contentView addSubview:tf];
            }

            UITextField *tf = (UITextField *)[cell.contentView viewWithTag:100];
            CGRect b = cell.contentView.bounds;
            tf.frame = CGRectMake(16.0f, 0, b.size.width - 32.0f, b.size.height);
            tf.text  = self.pendingServerAddress ?: @"";
            self.serverAddressField = tf;
            return cell;
        }

        UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"CertCell"];
        if (!cell) {
            cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1
                                          reuseIdentifier:@"CertCell"];
        }
        BOOL canSelect = (self.pendingServerAddress.length > 0);
        cell.textLabel.text       = @"Select Certificate";
        cell.textLabel.textColor  = canSelect
            ? [UIColor colorWithRed:0.05f green:0.42f blue:0.86f alpha:1.0f]
            : [UIColor grayColor];
        cell.detailTextLabel.textColor = [UIColor grayColor];
        cell.accessoryType  = canSelect ? UITableViewCellAccessoryDisclosureIndicator
                                        : UITableViewCellAccessoryNone;
        cell.selectionStyle = canSelect ? UITableViewCellSelectionStyleBlue
                                        : UITableViewCellSelectionStyleNone;
        return cell;
    }

    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"InfoCell"];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1
                                      reuseIdentifier:@"InfoCell"];
    }

    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    cell.accessoryType  = UITableViewCellAccessoryNone;
    cell.textLabel.textColor       = [UIColor blackColor];
    cell.detailTextLabel.textColor = [UIColor grayColor];
    cell.detailTextLabel.adjustsFontSizeToFitWidth = NO;

    UIView *oldTF = [cell.contentView viewWithTag:200];
    if (oldTF) [oldTF removeFromSuperview];

    SNDataManager *dm = [SNDataManager shared];
    NSDictionary *prof = [dm profileForIndex:self.profileIndex];

    switch (indexPath.section) {
        case SectionServer: {
            if (indexPath.row == 0) {
                cell.textLabel.text = @"Domain";

                UITextField *tf = [[UITextField alloc] init];
                tf.text                     = [prof objectForKey:@"server_address"] ?: @"";
                tf.placeholder              = @"hostname or IP";
                tf.autocorrectionType       = UITextAutocorrectionTypeNo;
                tf.autocapitalizationType   = UITextAutocapitalizationTypeNone;
                tf.keyboardType             = UIKeyboardTypeURL;
                tf.returnKeyType            = UIReturnKeyDone;
                tf.clearButtonMode          = UITextFieldViewModeWhileEditing;
                tf.delegate                 = self;
                tf.font                     = [UIFont systemFontOfSize:15.0f];
                tf.textColor                = [UIColor grayColor];
                tf.textAlignment            = NSTextAlignmentRight;
                tf.contentVerticalAlignment = UIControlContentVerticalAlignmentCenter;
                tf.autoresizingMask         = UIViewAutoresizingFlexibleWidth;
                tf.tag                      = 200;
                [cell.contentView addSubview:tf];
                self.registeredAddressField = tf;

                CGRect b = cell.contentView.bounds;
                tf.frame = CGRectMake(90.0f, 0, b.size.width - 106.0f, b.size.height);

            } else if (indexPath.row == 1) {
                NSString *addr = [prof objectForKey:@"server_address"];
                NSDictionary *dns = [dm cachedDNSForServerAddress:addr];
                cell.textLabel.text       = @"Resolved IP";
                cell.detailTextLabel.text = (dns && dns[@"ip"]) ? dns[@"ip"] : @"Waiting\xe2\x80\xa6";
            } else {
                NSString *addr = [prof objectForKey:@"server_address"];
                NSDictionary *dns = [dm cachedDNSForServerAddress:addr];
                cell.textLabel.text       = @"Port";
                cell.detailTextLabel.text = (dns && dns[@"port"])
                                                ? [dns[@"port"] description]
                                                : @"Waiting\xe2\x80\xa6";
            }
            break;
        }
        case SectionDevice: {
            cell.textLabel.text = @"Device ID";
            cell.detailTextLabel.text = [prof objectForKey:@"device_address"] ?: @"None";
            cell.detailTextLabel.adjustsFontSizeToFitWidth = YES;
            cell.detailTextLabel.minimumFontSize = 8.0f;
            break;
        }
        case SectionActions: {
            cell.textLabel.text      = @"Unregister Device";
            cell.textLabel.textColor = [UIColor redColor];
            cell.detailTextLabel.text = @"";
            cell.selectionStyle = UITableViewCellSelectionStyleBlue;
            break;
        }
    }

    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];

    if (![self isRegistered]) {
        if (indexPath.section == WizardSectionCert && self.pendingServerAddress.length > 0) {
            [self.serverAddressField resignFirstResponder];

            SFPFilePickerFilter *filter = [[SFPFilePickerFilter alloc] init];
            filter.allowedExtensions = @[@"pem"];

            SFPFilePickerViewController *picker =
                [[SFPFilePickerViewController alloc] initWithPath:nil
                                                           filter:filter
                                                         delegate:self];
            picker.showsCancelButton = NO;
            [self.navigationController pushViewController:picker animated:YES];
        }
        return;
    }

    if (indexPath.section == SectionActions && indexPath.row == 0) {
        [self _showUnregisterConfirmation];
    }
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    [textField resignFirstResponder];
    return YES;
}

- (void)textFieldDidEndEditing:(UITextField *)textField {
    NSString *trimmed = [textField.text stringByTrimmingCharactersInSet:
                         [NSCharacterSet whitespaceAndNewlineCharacterSet]];

    if (textField.tag == 100) {
        self.pendingServerAddress = trimmed;
        [self.tableView reloadData];

    } else if (textField.tag == 200) {
        NSString *current = [[[SNDataManager shared] profileForIndex:self.profileIndex] objectForKey:@"server_address"];
        if (trimmed.length > 0 && ![trimmed isEqualToString:current]) {
            [self _commitServerAddressChange:trimmed];
        } else if (trimmed.length == 0) {
            textField.text = current;
        }
    }
}

- (BOOL)textField:(UITextField *)textField
        shouldChangeCharactersInRange:(NSRange)range
        replacementString:(NSString *)string {
    if (textField.tag == 100) {
        NSString *updated = [textField.text stringByReplacingCharactersInRange:range
                                                                    withString:string];
        self.pendingServerAddress = [updated stringByTrimmingCharactersInSet:
                                     [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        NSIndexPath *certPath = [NSIndexPath indexPathForRow:0 inSection:WizardSectionCert];
        if ([self.tableView respondsToSelector:@selector(reloadRowsAtIndexPaths:withRowAnimation:)]) {
            [self.tableView reloadRowsAtIndexPaths:@[certPath]
                                 withRowAnimation:UITableViewRowAnimationNone];
        }
    }
    return YES;
}

- (void)filePicker:(SFPFilePickerViewController *)picker didSelectFileAtPath:(NSString *)path {
    self.pendingPEMPath = path;
    NSString *filename  = [path lastPathComponent];
    NSString *message   = [NSString stringWithFormat:
                           @"Import \"%@\" as the server certificate for %@?",
                           filename, self.pendingServerAddress];

    Class alertControllerClass = NSClassFromString(@"UIAlertController");
    if (alertControllerClass) {
        SEL createSel = NSSelectorFromString(@"alertControllerWithTitle:message:preferredStyle:");
        id (*create)(Class, SEL, id, id, NSInteger) =
            (id (*)(Class, SEL, id, id, NSInteger))objc_msgSend;
        id alert = create(alertControllerClass, createSel,
                          @"Confirm Certificate", message, 1 /* Alert */);

        Class actionClass = NSClassFromString(@"UIAlertAction");
        SEL actionSel     = NSSelectorFromString(@"actionWithTitle:style:handler:");
        id (*makeAction)(Class, SEL, id, NSInteger, id) =
            (id (*)(Class, SEL, id, NSInteger, id))objc_msgSend;

        id cancelAction = makeAction(actionClass, actionSel, @"Cancel", 1, nil);

        NSString *capturedAddress = self.pendingServerAddress;
        NSString *capturedPath    = path;
        __weak typeof(self) weakSelf = self;
        void (^confirmBlock)(id) = ^(id action) {
            [weakSelf _confirmImportFromPath:capturedPath serverAddress:capturedAddress];
        };
        id importAction = makeAction(actionClass, actionSel, @"Import", 0, confirmBlock);

        SEL addSel = NSSelectorFromString(@"addAction:");
        void (*addAction)(id, SEL, id) = (void (*)(id, SEL, id))objc_msgSend;
        addAction(alert, addSel, cancelAction);
        addAction(alert, addSel, importAction);

        SEL presentSel = NSSelectorFromString(@"presentViewController:animated:completion:");
        void (*present)(id, SEL, id, BOOL, id) = (void (*)(id, SEL, id, BOOL, id))objc_msgSend;
        present(picker, presentSel, alert, YES, nil);
    } else {
        UIAlertView *av = [[UIAlertView alloc]
                           initWithTitle:@"Confirm Certificate"
                                 message:message
                                delegate:self
                       cancelButtonTitle:@"Cancel"
                       otherButtonTitles:@"Import", nil];
        av.tag = kAlertTagPEMConfirm;
        [av show];
    }
}

- (void)_confirmImportFromPath:(NSString *)path serverAddress:(NSString *)serverAddress {
    BOOL success = [[SNDataManager shared] importProfileFromPEMAtPath:path
                                                        serverAddress:serverAddress
                                                         profileIndex:self.profileIndex];
    self.pendingPEMPath = nil;

    if (success) {
        self.pendingServerAddress = nil;
        [self.navigationController popToViewController:self animated:YES];
        self.title = [NSString stringWithFormat:@"Profile %ld", (long)self.profileIndex];
    } else {
        UIAlertView *av = [[UIAlertView alloc]
                           initWithTitle:@"Import Failed"
                                 message:@"Could not read or copy the selected .pem file. Make sure the file is a valid PEM certificate."
                                delegate:nil
                       cancelButtonTitle:@"OK"
                       otherButtonTitles:nil];
        [av show];
    }
}

- (void)_commitServerAddressChange:(NSString *)newAddress {
    NSString *path = [[SNDataManager shared] profilePathForIndex:self.profileIndex];
    NSMutableDictionary *profile =
        [NSMutableDictionary dictionaryWithContentsOfFile:path]
        ?: [NSMutableDictionary dictionary];
    profile[@"server_address"] = newAddress;
    [profile writeToFile:path atomically:YES];
    SNPostReloadConfig();
}

- (void)_performUnregister {
    SNDataManager *dm = [SNDataManager shared];

    [dm unregisterProfileAtIndex:self.profileIndex];

    if ([dm activeProfileIndex] == self.profileIndex) {
        NSInteger nextActive = 0;
        for (NSInteger i = 1; i <= 5; i++) {
            if (i != self.profileIndex && [dm profileExistsAtIndex:i]) {
                nextActive = i;
                break;
            }
        }
        if (nextActive > 0) {
            [dm setActiveProfileIndex:nextActive];
        } else {
            [dm setMainPrefValue:@NO forKey:@"enabled"];
            CFPreferencesSetAppValue(CFSTR("enabled"),
                                     (__bridge CFPropertyListRef)@NO,
                                     CFSTR("com.skyglow.sndp"));
            CFPreferencesAppSynchronize(CFSTR("com.skyglow.sndp"));
        }
    }

    SNPostReloadConfig();
    [self.navigationController popViewControllerAnimated:YES];
}

- (void)_showUnregisterConfirmation {
    NSString *msg = @"This will disable the daemon and delete your cryptographic keys. The server will be disconnected.";

    Class alertControllerClass = NSClassFromString(@"UIAlertController");
    if (alertControllerClass) {
        SEL createSel = NSSelectorFromString(@"alertControllerWithTitle:message:preferredStyle:");
        id (*create)(Class, SEL, id, id, NSInteger) =
            (id (*)(Class, SEL, id, id, NSInteger))objc_msgSend;
        id alert = create(alertControllerClass, createSel, @"Unregister?", msg, 1);

        Class actionClass = NSClassFromString(@"UIAlertAction");
        SEL actionSel = NSSelectorFromString(@"actionWithTitle:style:handler:");
        id (*makeAction)(Class, SEL, id, NSInteger, id) =
            (id (*)(Class, SEL, id, NSInteger, id))objc_msgSend;

        id cancelAction = makeAction(actionClass, actionSel, @"Cancel", 1, nil);

        __weak typeof(self) weakSelf = self;
        void (^unregBlock)(id) = ^(id action) { [weakSelf _performUnregister]; };
        id unregAction = makeAction(actionClass, actionSel, @"Unregister", 2 /* Destructive */, unregBlock);

        SEL addSel = NSSelectorFromString(@"addAction:");
        void (*addAction)(id, SEL, id) = (void (*)(id, SEL, id))objc_msgSend;
        addAction(alert, addSel, cancelAction);
        addAction(alert, addSel, unregAction);

        SEL presentSel = NSSelectorFromString(@"presentViewController:animated:completion:");
        void (*present)(id, SEL, id, BOOL, id) = (void (*)(id, SEL, id, BOOL, id))objc_msgSend;
        present(self, presentSel, alert, YES, nil);
    } else {
        UIAlertView *av = [[UIAlertView alloc]
                           initWithTitle:@"Unregister?"
                                 message:msg
                                delegate:self
                       cancelButtonTitle:@"Cancel"
                       otherButtonTitles:@"Unregister", nil];
        av.tag = kAlertTagUnregister;
        [av show];
    }
}

- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex {
    if (alertView.tag == kAlertTagPEMConfirm) {
        if (buttonIndex == 1) {
            [self _confirmImportFromPath:self.pendingPEMPath
                           serverAddress:self.pendingServerAddress];
        } else {
            self.pendingPEMPath = nil;
        }
    } else if (alertView.tag == kAlertTagUnregister) {
        if (buttonIndex == 1) {
            [self _performUnregister];
        }
    }
}

@end
