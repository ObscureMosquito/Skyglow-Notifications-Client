#import "SNServerInfoViewController.h"
#import "SNDataManager.h"
#import "SNChannelGateway.h"
#import "SNDeferredActivity.h"
#import "../libraries/SFPFilePicker/include/SFPFilePicker.h"
#import <CoreFoundation/CoreFoundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

/* SFPFilePicker is a non-PS UIViewController subclass, so iOS 4-5
 * PSRootController hits the same "unrecognized selector" crash on
 * back-pop as our own non-PS VCs do.  Same fix: empty stubs.  We can't
 * edit the library source from here, so attach them via a category. */
@interface SFPFilePickerViewController (SkyglowPSStubs)
- (void)setRootController:(id)controller;
- (void)setParentController:(id)controller;
- (void)setSpecifier:(id)specifier;
@end

@implementation SFPFilePickerViewController (SkyglowPSStubs)
- (void)setRootController:(id)controller   {}
- (void)setParentController:(id)controller {}
- (void)setSpecifier:(id)specifier         {}
- (void)willResignActive                   {}
- (void)willBecomeActive                   {}
@end

typedef enum {
    WizardSectionServer = 0,
    WizardSectionCert   = 1,
    WizardSectionCount  = 2
} WizardSection;

typedef enum {
    WizardCertRowAuto   = 0,
    WizardCertRowManual = 1,
    WizardCertRowCount  = 2
} WizardCertRow;

typedef enum {
    SectionServer  = 0,
    SectionDevice  = 1,
    SectionActions = 2,
    SectionCount   = 3
} ServerInfoSection;

static const NSInteger kAlertTagPEMConfirm   = 1;
static const NSInteger kAlertTagUnregister   = 2;
static const NSInteger kAlertTagFetchInstall = 3;


@interface SNServerInfoViewController () <UIAlertViewDelegate, UITextFieldDelegate, SFPFilePickerDelegate>

@property (nonatomic, strong) NSString    *pendingServerAddress;
@property (nonatomic, strong) NSString    *pendingPEMPath;
@property (nonatomic, strong) NSString    *pendingFetchedPEM;
@property (nonatomic, strong) NSString    *pendingFetchedAddress;
@property (nonatomic, assign) BOOL         autoFetchInProgress;
@property (nonatomic, assign) BOOL         unregisterInFlight;
@property (nonatomic, assign) BOOL         unregisterRequestInFlight;
@property (nonatomic, assign) BOOL         profileSaveInFlight;
@property (nonatomic, assign) BOOL         profileSaveRequestInFlight;
@property (nonatomic, assign) NSInteger    profileSaveWizardRow;
@property (nonatomic, strong) NSString    *profileSaveStatusText;
@property (nonatomic, strong) SNDeferredActivity *unregisterActivity;
@property (nonatomic, strong) SNDeferredActivity *profileSaveActivity;
@property (nonatomic, unsafe_unretained) UITextField *serverAddressField;
@property (nonatomic, unsafe_unretained) UITextField *registeredAddressField;

@end

@implementation SNServerInfoViewController

/* iOS 4-5 PSRootController calls these on every pushed VC during the
 * back-pop sequence, even on plain UIViewControllers.  Crashes with
 * "unrecognized selector" otherwise. */
- (void)setRootController:(id)controller   {}
- (void)setParentController:(id)controller {}
- (void)setSpecifier:(id)specifier         {}
- (void)willResignActive                   {}
- (void)willBecomeActive                   {}

- (id)init {
    return [self initWithProfileIndex:[[SNDataManager shared] activeProfileIndex]];
}

- (id)initWithProfileIndex:(NSInteger)index {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        _profileIndex = index;
        _profileSaveWizardRow = -1;
        self.title = [NSString stringWithFormat:@"Profile %ld", (long)index];
    }
    return self;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    BOOL busy = self.profileSaveRequestInFlight || self.unregisterRequestInFlight;
    [self.navigationItem setHidesBackButton:busy animated:NO];
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

        UIView *iconGroup = [[[UIView alloc] initWithFrame:CGRectMake(startX, topPad, totalGroupWidth, iconSize)] autorelease];
        iconGroup.backgroundColor = [UIColor clearColor];
        iconGroup.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleRightMargin;

        UIImage *webIcon = [UIImage imageWithContentsOfFile:[bundle pathForResource:@"web" ofType:@"png"]];
        UIImageView *webIconView = [[[UIImageView alloc] initWithImage:webIcon] autorelease];
        webIconView.contentMode   = UIViewContentModeScaleAspectFit;
        webIconView.clipsToBounds = YES;
        webIconView.frame = CGRectMake(0, 0, iconSize, iconSize);

        UILabel *arrowLabel = [[[UILabel alloc] initWithFrame:CGRectMake(iconSize + spacing, 0, arrowWidth, iconSize)] autorelease];
        arrowLabel.text = @"➔";
        arrowLabel.font = [UIFont boldSystemFontOfSize:25.0f];
        arrowLabel.textColor = [UIColor colorWithRed:0.55f green:0.55f blue:0.58f alpha:1.0f];
        arrowLabel.shadowColor = [UIColor colorWithWhite:1.0f alpha:0.7f];
        arrowLabel.shadowOffset = CGSizeMake(0, 1);
        arrowLabel.backgroundColor = [UIColor clearColor];
        arrowLabel.textAlignment = NSTextAlignmentCenter;

        UIImage *settingsIcon = [UIImage imageWithContentsOfFile:[bundle pathForResource:@"icon-settings" ofType:@"png"]];
        UIImageView *settingsIconView = [[[UIImageView alloc] initWithImage:settingsIcon] autorelease];
        settingsIconView.contentMode   = UIViewContentModeScaleAspectFit;
        settingsIconView.clipsToBounds = YES;

        CGFloat settingsYOffset = (iconSize - smallIconSize) / 2.0f;
        CGFloat settingsXOrigin = iconSize + spacing + arrowWidth + spacing;

        settingsIconView.frame = CGRectMake(settingsXOrigin, settingsYOffset, smallIconSize, smallIconSize);
        
        [iconGroup addSubview:webIconView];
        [iconGroup addSubview:arrowLabel];
        [iconGroup addSubview:settingsIconView];

        CGFloat iconGap   = 10.0f;
        CGFloat titleGap  = 4.0f;
        CGFloat bodyGap   = 12.0f;
        CGFloat botPad    = 18.0f;
        CGFloat sideInset = 24.0f;

        UILabel *titleLabel     = [[[UILabel alloc] init] autorelease];
        titleLabel.text         = @"Skyglow Notifications";
        titleLabel.font         = [UIFont boldSystemFontOfSize:17.0f];
        titleLabel.textColor    = [UIColor colorWithRed:0.18f green:0.18f blue:0.18f alpha:1.0f];
        titleLabel.shadowColor  = [UIColor colorWithWhite:1.0f alpha:0.7f];
        titleLabel.shadowOffset = CGSizeMake(0, 1);
        titleLabel.textAlignment     = NSTextAlignmentCenter;
        titleLabel.backgroundColor   = [UIColor clearColor];
        titleLabel.autoresizingMask  = UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleRightMargin;
        CGFloat titleY = topPad + iconSize + iconGap;
        [titleLabel sizeToFit];
        titleLabel.frame = CGRectMake((w - titleLabel.frame.size.width) / 2.0f, titleY, titleLabel.frame.size.width, titleLabel.frame.size.height);

        UILabel *bodyLabel      = [[[UILabel alloc] init] autorelease];
        bodyLabel.text          = @"Enter your server address below, then select\nyour server\xe2\x80\x99s public certificate to get started.";
        bodyLabel.font          = [UIFont systemFontOfSize:13.0f];
        bodyLabel.textColor     = [UIColor colorWithRed:0.38f green:0.38f blue:0.42f alpha:1.0f];
        bodyLabel.shadowColor   = [UIColor colorWithWhite:1.0f alpha:0.6f];
        bodyLabel.shadowOffset  = CGSizeMake(0, 1);
        bodyLabel.textAlignment    = NSTextAlignmentCenter;
        bodyLabel.backgroundColor  = [UIColor clearColor];
        bodyLabel.numberOfLines    = 0;
        bodyLabel.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleRightMargin;
        CGFloat bodyY = titleY + titleLabel.frame.size.height + titleGap;
        CGSize bodyFit = [bodyLabel sizeThatFits:CGSizeMake(w - sideInset * 2.0f, 999.0f)];
        bodyLabel.frame = CGRectMake((w - bodyFit.width) / 2.0f, bodyY, bodyFit.width, bodyFit.height);

        CGFloat totalH = bodyY + bodyFit.height + bodyGap + botPad;
        UIView *header = [[[UIView alloc] initWithFrame:CGRectMake(0, 0, w, totalH)] autorelease];
        header.backgroundColor = [UIColor clearColor];
        header.autoresizingMask = UIViewAutoresizingFlexibleWidth;

        [header addSubview:iconGroup];

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
    if (![self isRegistered]) {
        return (section == WizardSectionCert) ? WizardCertRowCount : 1;
    }
    switch (section) {
        case SectionServer:  return 3;
        case SectionDevice:  return 1;
        case SectionActions: return 1;
        default: return 0;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (![self isRegistered]) {
        switch (section) {
            case WizardSectionServer: return @"Server Address";
            case WizardSectionCert:   return @"Server Setup";
            default: return nil;
        }
    }
    switch (section) {
        case SectionServer: return @"Server Details";
        case SectionDevice: return @"Identity";
        default: return nil;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (![self isRegistered]) {
        switch (section) {
            case WizardSectionServer:
                return @"Enter the hostname or IP address of your Skyglow notification server.";
            case WizardSectionCert:
                return @"Fetch the certificate automatically, or import a .pem file manually from disk";
            default: return nil;
        }
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
                cell = [[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                              reuseIdentifier:@"TFCell"] autorelease];
                cell.selectionStyle = UITableViewCellSelectionStyleNone;

                UITextField *tf = [[[UITextField alloc] init] autorelease];
                tf.placeholder              = @"Hostname or IP address";
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

        BOOL isAuto = (indexPath.row == WizardCertRowAuto);
        NSString *reuseID = isAuto ? @"AutoCertCell" : @"ManualCertCell";
        UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:reuseID];
        if (!cell) {
            cell = [[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                          reuseIdentifier:reuseID] autorelease];
        }

        BOOL hasAddress = (self.pendingServerAddress.length > 0);
        BOOL canSelect  = hasAddress && !self.autoFetchInProgress && !self.profileSaveRequestInFlight;
        BOOL isSavingThisRow = self.profileSaveInFlight && self.profileSaveWizardRow == indexPath.row;
        UIColor *enabledTint = [UIColor colorWithRed:0.05f green:0.42f blue:0.86f alpha:1.0f];

        if (isAuto) {
            if (isSavingThisRow) {
                cell.textLabel.text = self.profileSaveStatusText ?: @"Saving\xe2\x80\xa6";
            } else {
                cell.textLabel.text = self.autoFetchInProgress ? @"Fetching\xe2\x80\xa6"
                                                               : @"Fetch Automatically";
            }
            if (self.autoFetchInProgress || isSavingThisRow) {
                UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc]
                    initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
                [spinner startAnimating];
                cell.accessoryView = spinner;
                [spinner release];
            } else {
                cell.accessoryView = nil;
                cell.accessoryType = hasAddress ? UITableViewCellAccessoryDisclosureIndicator
                                                : UITableViewCellAccessoryNone;
            }
        } else {
            cell.textLabel.text = isSavingThisRow ? (self.profileSaveStatusText ?: @"Importing\xe2\x80\xa6")
                                                  : @"Import From Disk";
            if (isSavingThisRow) {
                UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc]
                    initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
                [spinner startAnimating];
                cell.accessoryView = spinner;
                [spinner release];
                cell.accessoryType = UITableViewCellAccessoryNone;
            } else {
                cell.accessoryView = nil;
                cell.accessoryType = canSelect ? UITableViewCellAccessoryDisclosureIndicator
                                               : UITableViewCellAccessoryNone;
            }
        }

        cell.textLabel.textColor = (canSelect || isSavingThisRow) ? enabledTint : [UIColor grayColor];
        cell.selectionStyle      = canSelect ? UITableViewCellSelectionStyleBlue
                                             : UITableViewCellSelectionStyleNone;
        return cell;
    }

    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"InfoCell"];
    if (!cell) {
        cell = [[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1
                                      reuseIdentifier:@"InfoCell"] autorelease];
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

                UITextField *tf = [[[UITextField alloc] init] autorelease];
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
            cell.textLabel.text      = self.unregisterInFlight ? @"Unregistering\xe2\x80\xa6" : @"Unregister Device";
            cell.textLabel.textColor = self.unregisterInFlight ? [UIColor grayColor] : [UIColor redColor];
            cell.detailTextLabel.text = @"";
            if (self.unregisterInFlight) {
                UIActivityIndicatorView *spin = [[UIActivityIndicatorView alloc]
                    initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
                [spin startAnimating];
                cell.accessoryView = spin;
                [spin release];
                cell.selectionStyle = UITableViewCellSelectionStyleNone;
            } else {
                cell.accessoryView = nil;
                cell.selectionStyle = UITableViewCellSelectionStyleBlue;
            }
            break;
        }
    }

    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];

    if (![self isRegistered]) {
        if (indexPath.section != WizardSectionCert) return;
        if (self.pendingServerAddress.length == 0 ||
            self.autoFetchInProgress ||
            self.profileSaveRequestInFlight) return;

        [self.view endEditing:YES];

        if (indexPath.row == WizardCertRowAuto) {
            [self _beginAutoFetchCertificate];
        } else {
            SFPFilePickerFilter *filter = [[SFPFilePickerFilter alloc] init];
            filter.allowedExtensions = @[@"pem"];

            SFPFilePickerViewController *picker =
                [[SFPFilePickerViewController alloc] initWithPath:nil
                                                           filter:filter
                                                         delegate:self];
            picker.showsCancelButton = NO;
            [self.navigationController pushViewController:picker animated:YES];
            [picker release];
            [filter release];
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
        if ([self.tableView respondsToSelector:@selector(reloadRowsAtIndexPaths:withRowAnimation:)]) {
            [self.tableView reloadRowsAtIndexPaths:@[
                [NSIndexPath indexPathForRow:WizardCertRowAuto   inSection:WizardSectionCert],
                [NSIndexPath indexPathForRow:WizardCertRowManual inSection:WizardSectionCert],
            ] withRowAnimation:UITableViewRowAnimationNone];
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

        NSString *capturedAddress = [[self.pendingServerAddress copy] autorelease];
        NSString *capturedPath    = [[path copy] autorelease];
        void (^confirmBlock)(id) = ^(id action) {
            [self _confirmImportFromPath:capturedPath serverAddress:capturedAddress];
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
        [av release];
    }
}

- (void)_beginAutoFetchCertificate {
    NSString *address = self.pendingServerAddress;
    if (address.length == 0 || self.autoFetchInProgress || self.profileSaveRequestInFlight) return;

    self.autoFetchInProgress = YES;
    [self.navigationItem setHidesBackButton:YES animated:YES];
    [self _reloadCertSections];

    [[SNDataManager shared] fetchServerCertificateForAddress:address
                                                  completion:^(NSString *pem, NSString *errorMessage) {
        self.autoFetchInProgress = NO;
        [self.navigationItem setHidesBackButton:NO animated:YES];
        [self _reloadCertSections];

        if (errorMessage) {
            UIAlertView *av = [[UIAlertView alloc] initWithTitle:@"Auto-Fetch Failed"
                                                         message:errorMessage
                                                        delegate:nil
                                               cancelButtonTitle:@"OK"
                                               otherButtonTitles:nil];
            [av show];
            [av release];
            return;
        }
        [self _confirmInstallFetchedPEM:pem serverAddress:address];
    }];
}

- (void)_reloadCertSections {
    if (![self.tableView respondsToSelector:@selector(reloadSections:withRowAnimation:)]) {
        [self.tableView reloadData];
        return;
    }
    [self.tableView reloadSections:[NSIndexSet indexSetWithIndex:WizardSectionCert]
                  withRowAnimation:UITableViewRowAnimationNone];
}

- (void)_confirmInstallFetchedPEM:(NSString *)pem serverAddress:(NSString *)serverAddress {
    NSDictionary *info = [[SNDataManager shared] parseCertificatePEM:pem];
    NSString *subject = info[@"subject"] ?: @"(unknown subject)";
    NSString *issuer  = info[@"issuer"]  ?: @"(unknown issuer)";
    NSString *fingerprint = info[@"fingerprint"] ?: @"(unavailable)";
    NSString *message = [NSString stringWithFormat:
        @"This certificate was fetched over an unauthenticated connection. Confirm the SHA-256 fingerprint matches your server before installing it as the pinned certificate.\n\n"
        @"Server: %@\nSubject: %@\nIssuer: %@\n\nSHA-256:\n%@",
        serverAddress, subject, issuer, fingerprint];

    Class alertControllerClass = NSClassFromString(@"UIAlertController");
    if (alertControllerClass) {
        SEL createSel = NSSelectorFromString(@"alertControllerWithTitle:message:preferredStyle:");
        id (*create)(Class, SEL, id, id, NSInteger) =
            (id (*)(Class, SEL, id, id, NSInteger))objc_msgSend;
        id alert = create(alertControllerClass, createSel,
                          @"Confirm Certificate", message, 1 /* Alert */);

        Class actionClass = NSClassFromString(@"UIAlertAction");
        SEL actionSel = NSSelectorFromString(@"actionWithTitle:style:handler:");
        id (*makeAction)(Class, SEL, id, NSInteger, id) =
            (id (*)(Class, SEL, id, NSInteger, id))objc_msgSend;

        id cancelAction = makeAction(actionClass, actionSel, @"Cancel", 1, nil);
        NSString *capturedAddress = serverAddress;
        NSString *capturedPEM     = pem;
        void (^installBlock)(id) = ^(id action) {
            [self _commitInstallFetchedPEM:capturedPEM serverAddress:capturedAddress];
        };
        id installAction = makeAction(actionClass, actionSel, @"Install", 0, installBlock);

        SEL addSel = NSSelectorFromString(@"addAction:");
        void (*addAction)(id, SEL, id) = (void (*)(id, SEL, id))objc_msgSend;
        addAction(alert, addSel, cancelAction);
        addAction(alert, addSel, installAction);

        SEL presentSel = NSSelectorFromString(@"presentViewController:animated:completion:");
        void (*present)(id, SEL, id, BOOL, id) = (void (*)(id, SEL, id, BOOL, id))objc_msgSend;
        present(self, presentSel, alert, YES, nil);
    } else {
        self.pendingFetchedPEM     = pem;
        self.pendingFetchedAddress = serverAddress;
        UIAlertView *av = [[UIAlertView alloc]
                           initWithTitle:@"Confirm Certificate"
                                 message:message
                                delegate:self
                       cancelButtonTitle:@"Cancel"
                       otherButtonTitles:@"Install", nil];
        av.tag = kAlertTagFetchInstall;
        [av show];
        [av release];
    }
}

- (void)_commitInstallFetchedPEM:(NSString *)pem serverAddress:(NSString *)serverAddress {
    [self _saveProfileWithServerAddress:serverAddress
                         certificatePEM:pem
                             statusText:@"Installing\xe2\x80\xa6"
                           failureTitle:@"Install Failed"
                         wizardSourceRow:WizardCertRowAuto
                              onSuccess:^{
        self.pendingServerAddress = nil;
        [self _updateTableHeaderView];
        [self.navigationController popToViewController:self animated:YES];
        self.title = [NSString stringWithFormat:@"Profile %ld", (long)self.profileIndex];
        [self.tableView reloadData];
    }];
}

- (void)_confirmImportFromPath:(NSString *)path serverAddress:(NSString *)serverAddress {
    self.pendingPEMPath = nil;
    if (![self _beginProfileSaveActivityWithStatusText:@"Importing\xe2\x80\xa6"
                                       wizardSourceRow:WizardCertRowManual]) {
        return;
    }

    if (self.navigationController.topViewController != self) {
        [self.navigationController popToViewController:self animated:YES];
    }

    NSString *pathCopy = [[path copy] autorelease];
    NSString *addressCopy = [[serverAddress copy] autorelease];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
        NSString *pem = [[NSString alloc] initWithContentsOfFile:pathCopy
                                                        encoding:NSUTF8StringEncoding
                                                           error:nil];
        BOOL valid = ([pem length] > 0 && [[SNDataManager shared] parseCertificatePEM:pem] != nil);
        NSString *pemResult = valid ? [pem retain] : nil;
        [pem release];

        dispatch_async(dispatch_get_main_queue(), ^{
            if (!valid) {
                [self _finishProfileSaveActivityWithCompletion:^{
                    UIAlertView *av = [[UIAlertView alloc]
                                       initWithTitle:@"Import Failed"
                                             message:@"Could not read the selected .pem file. Make sure the file is a valid PEM certificate."
                                            delegate:nil
                                   cancelButtonTitle:@"OK"
                                   otherButtonTitles:nil];
                    [av show];
                    [av release];
                }];
                [pemResult release];
                return;
            }

            [self _sendProfileSaveWithServerAddress:addressCopy
                                     certificatePEM:pemResult
                                       failureTitle:@"Import Failed"
                                          onSuccess:^{
                self.pendingServerAddress = nil;
                [self _updateTableHeaderView];
                self.title = [NSString stringWithFormat:@"Profile %ld", (long)self.profileIndex];
                [self.tableView reloadData];
            }];
            [pemResult release];
        });
        [pool release];
    });
}

- (void)_commitServerAddressChange:(NSString *)newAddress {
    [self _saveProfileWithServerAddress:newAddress
                         certificatePEM:nil
                             statusText:@"Saving\xe2\x80\xa6"
                           failureTitle:@"Save Failed"
                         wizardSourceRow:-1
                              onSuccess:^{
        self.title = [NSString stringWithFormat:@"Profile %ld", (long)self.profileIndex];
        [self.tableView reloadData];
    }];
}

- (void)_saveProfileWithServerAddress:(NSString *)serverAddress
                       certificatePEM:(NSString *)certificatePEM
                           statusText:(NSString *)statusText
                         failureTitle:(NSString *)failureTitle
                       wizardSourceRow:(NSInteger)wizardSourceRow
                            onSuccess:(void (^)(void))successBlock {
    if (![self _beginProfileSaveActivityWithStatusText:statusText
                                       wizardSourceRow:wizardSourceRow]) {
        return;
    }
    [self _sendProfileSaveWithServerAddress:serverAddress
                             certificatePEM:certificatePEM
                               failureTitle:failureTitle
                                  onSuccess:successBlock];
}

- (BOOL)_beginProfileSaveActivityWithStatusText:(NSString *)statusText
                                wizardSourceRow:(NSInteger)wizardSourceRow {
    if (self.profileSaveRequestInFlight) return NO;
    self.profileSaveRequestInFlight = YES;
    self.profileSaveWizardRow = wizardSourceRow;
    self.profileSaveStatusText = statusText ?: @"Saving\xe2\x80\xa6";
    [self.navigationItem setHidesBackButton:YES animated:YES];
    self.tableView.allowsSelection = NO;

    self.profileSaveActivity = [[[SNDeferredActivity alloc] initWithShowBlock:^{
        self.profileSaveInFlight = YES;
        [self.tableView reloadData];
    } hideBlock:^{
        self.profileSaveInFlight = NO;
        [self.tableView reloadData];
    }] autorelease];
    [self.profileSaveActivity begin];
    return YES;
}

- (void)_finishProfileSaveActivityWithCompletion:(void (^)(void))completion {
    SNDeferredActivity *activity = [self.profileSaveActivity retain];
    [activity finishWithCompletion:^{
        self.profileSaveRequestInFlight = NO;
        self.profileSaveActivity = nil;
        self.profileSaveWizardRow = -1;
        self.profileSaveStatusText = nil;
        [self.navigationItem setHidesBackButton:NO animated:YES];
        self.tableView.allowsSelection = YES;
        if (completion) completion();
    }];
    [activity release];
}

- (void)_sendProfileSaveWithServerAddress:(NSString *)serverAddress
                           certificatePEM:(NSString *)certificatePEM
                             failureTitle:(NSString *)failureTitle
                                onSuccess:(void (^)(void))successBlock {
    NSInteger idx = self.profileIndex;
    [SNChannelGateway saveProfileAtIndex:idx
                           serverAddress:serverAddress
                          certificatePEM:certificatePEM
                              completion:^(BOOL ok, NSString *message) {
        [self _finishProfileSaveActivityWithCompletion:^{
            if (!ok) {
                UIAlertView *av = [[UIAlertView alloc] initWithTitle:failureTitle ?: @"Save Failed"
                                                             message:message ?: @"The daemon did not respond."
                                                            delegate:nil
                                                   cancelButtonTitle:@"OK"
                                                   otherButtonTitles:nil];
                [av show];
                [av release];
                [self.tableView reloadData];
                return;
            }

            if (successBlock) successBlock();
        }];
    }];
}

- (void)_performUnregister {
    if (_unregisterRequestInFlight) return;
    _unregisterRequestInFlight = YES;

    [self.navigationItem setHidesBackButton:YES animated:YES];
    self.tableView.allowsSelection = NO;

    self.unregisterActivity = [[[SNDeferredActivity alloc] initWithShowBlock:^{
        self.unregisterInFlight = YES;
        [self.tableView reloadData];
    } hideBlock:^{
        self.unregisterInFlight = NO;
        [self.tableView reloadData];
    }] autorelease];
    [self.unregisterActivity begin];

    NSInteger idx = self.profileIndex;
    [SNChannelGateway deleteProfileAtIndex:idx
                                completion:^(BOOL ok, NSString *message) {
        SNDeferredActivity *activity = [self.unregisterActivity retain];
        [activity finishWithCompletion:^{
            self.unregisterRequestInFlight = NO;
            self.unregisterActivity = nil;
            [self.navigationItem setHidesBackButton:NO animated:YES];
            self.tableView.allowsSelection = YES;

            if (!ok) {
                UIAlertView *av = [[UIAlertView alloc] initWithTitle:@"Could Not Unregister"
                                                             message:message ?: @"The daemon did not respond."
                                                            delegate:nil
                                                   cancelButtonTitle:@"OK"
                                                   otherButtonTitles:nil];
                [av show];
                [av release];
                return;
            }

            [self.navigationController popViewControllerAnimated:YES];
        }];
        [activity release];
    }];
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

        void (^unregBlock)(id) = ^(id action) { [self _performUnregister]; };
        id unregAction = makeAction(actionClass, actionSel, @"Unregister", 2, unregBlock);

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
        [av release];
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
    } else if (alertView.tag == kAlertTagFetchInstall) {
        NSString *pem  = [[self.pendingFetchedPEM retain] autorelease];
        NSString *addr = [[self.pendingFetchedAddress retain] autorelease];
        self.pendingFetchedPEM     = nil;
        self.pendingFetchedAddress = nil;
        if (buttonIndex == 1 && [pem length] > 0) {
            [self _commitInstallFetchedPEM:pem serverAddress:addr];
        }
    } else if (alertView.tag == kAlertTagUnregister) {
        if (buttonIndex == 1) {
            [self _performUnregister];
        }
    }
}

- (void)dealloc {
    [_pendingServerAddress release];
    [_pendingPEMPath release];
    [_pendingFetchedPEM release];
    [_pendingFetchedAddress release];
    [_profileSaveStatusText release];
    [_unregisterActivity release];
    [_profileSaveActivity release];

    [super dealloc];
}

@end
