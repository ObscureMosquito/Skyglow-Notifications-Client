#import "SNServerInfoViewController.h"
#import "SNPaneHeader.h"
#import "SNDataManager.h"
#import "SNChannelGateway.h"
#import "SNDeferredActivity.h"
#import "../libraries/SFPFilePicker/include/SFPFilePicker.h"
#import <CoreFoundation/CoreFoundation.h>
#import <QuartzCore/QuartzCore.h>
#import "SNAlert.h"
#import "SNInterfaceColors.h"

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

@interface SNServerInfoViewController () <UITextFieldDelegate, SFPFilePickerDelegate>

@property (nonatomic, strong) NSString    *pendingServerAddress;
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
@property (nonatomic, assign) BOOL         importingRegIdentity;
@property (nonatomic, assign) BOOL         regIdentitySaveInFlight;

@end

@implementation SNServerInfoViewController

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
    self.importingRegIdentity = NO;
    BOOL busy = self.profileSaveRequestInFlight || self.unregisterRequestInFlight;
    [self.navigationItem setHidesBackButton:busy animated:NO];
    [self _updateTableHeaderView];
    [self.tableView reloadData];
}

- (void)_updateTableHeaderView {
    if ([self isRegistered]) {
        self.tableView.tableHeaderView = nil;
        return;
    }

    CGFloat iconSize      = 62.0f;
    CGFloat smallIconSize = 55.5f;
    CGFloat arrowWidth    = 30.0f;
    CGFloat spacing       = 16.0f;
    CGFloat totalGroupWidth = iconSize + spacing + arrowWidth + spacing + smallIconSize;

    NSBundle *bundle = [NSBundle bundleForClass:[self class]];

    UIView *iconGroup = [[[UIView alloc] initWithFrame:CGRectMake(0, 0, totalGroupWidth, iconSize)] autorelease];
    iconGroup.backgroundColor = [UIColor clearColor];

    UIImage *webIcon = [UIImage imageWithContentsOfFile:[bundle pathForResource:@"web" ofType:@"png"]];
    UIImageView *webIconView = [[[UIImageView alloc] initWithImage:webIcon] autorelease];
    webIconView.contentMode   = UIViewContentModeScaleAspectFit;
    webIconView.clipsToBounds = YES;
    webIconView.frame = CGRectMake(0, 0, iconSize, iconSize);

    UILabel *arrowLabel = [[[UILabel alloc] initWithFrame:CGRectMake(iconSize + spacing, 0, arrowWidth, iconSize)] autorelease];
    arrowLabel.text = @"\u2794";
    arrowLabel.font = [UIFont boldSystemFontOfSize:25.0f];
    arrowLabel.textColor = SNTertiaryLabelColor([UIColor colorWithRed:0.55f green:0.55f blue:0.58f alpha:1.0f]);
    arrowLabel.shadowColor = SNLegacyTextShadowColor([UIColor colorWithWhite:1.0f alpha:0.7f]);
    arrowLabel.shadowOffset = CGSizeMake(0, 1);
    arrowLabel.backgroundColor = [UIColor clearColor];
    arrowLabel.textAlignment = NSTextAlignmentCenter;

    UIImage *settingsIcon = [UIImage imageWithContentsOfFile:[bundle pathForResource:@"icon-settings" ofType:@"png"]];
    UIImageView *settingsIconView = [[[UIImageView alloc] initWithImage:settingsIcon] autorelease];
    settingsIconView.contentMode   = UIViewContentModeScaleAspectFit;
    settingsIconView.clipsToBounds = YES;
    settingsIconView.frame = CGRectMake(iconSize + spacing + arrowWidth + spacing,
                                        (iconSize - smallIconSize) / 2.0f,
                                        smallIconSize, smallIconSize);

    [iconGroup addSubview:webIconView];
    [iconGroup addSubview:arrowLabel];
    [iconGroup addSubview:settingsIconView];

    self.tableView.tableHeaderView = SNPaneHeaderViewCreate(
        self.tableView.bounds.size.width, iconGroup,
        @"Enter your server address below, then select\nyour server's public certificate to get started.");
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
        case SectionDevice:  return [self _deviceIsRegistered] ? 1 : 2;
        case SectionActions: return 1;
        default: return 0;
    }
}

- (SNRegistrationStatus)_registrationStatus {
    return [[SNDataManager shared] registrationStatusForProfileAtIndex:self.profileIndex];
}

- (BOOL)_deviceIsRegistered {
    return [self _registrationStatus] == SNRegistrationRegistered;
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

- (UIView *)tableView:(UITableView *)tableView viewForFooterInSection:(NSInteger)section {
    if (![self isRegistered] || section != SectionDevice) return nil;

    SNRegistrationStatus status = [self _registrationStatus];
    CGFloat width = self.tableView.bounds.size.width;
    if (width < 10.0f) width = 320.0f;

    NSString *text;
    switch (status) {
        case SNRegistrationRegistered:
            text = @"Registered with this server."; break;
        case SNRegistrationNeedsCertificate:
            text = @"This server only accepts registrations authorized by a certificate. Import the .pem its operator issued you."; break;
        default:
            text = @"Not registered yet."; break;
    }

    UIFont *font = [UIFont systemFontOfSize:13.0f];
    CGFloat textLeft  = 16.0f + 10.0f + 8.0f;
    CGFloat textWidth = width - textLeft - 16.0f;

    UILabel *label = [[[UILabel alloc] init] autorelease];
    label.text          = text;
    label.font          = font;
    label.textColor     = SNSecondaryLabelColor([UIColor grayColor]);
    label.backgroundColor = [UIColor clearColor];
    label.numberOfLines = 0;
    label.lineBreakMode = NSLineBreakByWordWrapping;

    CGSize textSize = [text sizeWithFont:font
                       constrainedToSize:CGSizeMake(textWidth, 200.0f)
                           lineBreakMode:NSLineBreakByWordWrapping];
    label.frame = CGRectMake(textLeft, 8.0f, textWidth, textSize.height);

    UIView *dot = [[[UIView alloc] initWithFrame:CGRectMake(18.0f, 11.4f, 9.0f, 9.0f)] autorelease];
    if (status == SNRegistrationRegistered) {
        dot.backgroundColor = SNSystemGreenColor([UIColor colorWithRed:0.20f green:0.72f blue:0.30f alpha:1.0f]);
    } else if (status == SNRegistrationNeedsCertificate) {
        dot.backgroundColor = SNSystemRedColor([UIColor redColor]);
    } else {
        dot.backgroundColor = SNSecondaryLabelColor([UIColor grayColor]);
    }
    dot.layer.cornerRadius = 5.0f;
    dot.layer.masksToBounds = YES;

    UIView *footer = [[[UIView alloc] initWithFrame:
        CGRectMake(0, 0, width, textSize.height + 18.0f)] autorelease];
    footer.backgroundColor = [UIColor clearColor];
    [footer addSubview:dot];
    [footer addSubview:label];
    return footer;
}

- (CGFloat)tableView:(UITableView *)tableView heightForFooterInSection:(NSInteger)section {
    UIView *footer = [self tableView:tableView viewForFooterInSection:section];
    if (footer) return footer.frame.size.height;

    NSString *title = [self tableView:tableView titleForFooterInSection:section];
    if ([title length] == 0) return 0.0f;

    CGFloat width = self.tableView.bounds.size.width;
    if (width < 10.0f) width = 320.0f;
    CGSize size = [title sizeWithFont:[UIFont systemFontOfSize:13.0f]
                    constrainedToSize:CGSizeMake(width - 32.0f, 200.0f)
                        lineBreakMode:NSLineBreakByWordWrapping];
    return size.height + 18.0f;
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
        UIColor *enabledTint = SNSystemBlueColor([UIColor colorWithRed:0.05f green:0.42f blue:0.86f alpha:1.0f]);

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

        cell.textLabel.textColor = (canSelect || isSavingThisRow) ? enabledTint : SNSecondaryLabelColor([UIColor grayColor]);
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
    cell.textLabel.textColor       = SNLabelColor([UIColor blackColor]);
    cell.detailTextLabel.textColor = SNSecondaryLabelColor([UIColor grayColor]);
    cell.detailTextLabel.adjustsFontSizeToFitWidth = NO;
    cell.detailTextLabel.text = @"";

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
                tf.textColor                = SNSecondaryLabelColor([UIColor grayColor]);
                tf.textAlignment            = NSTextAlignmentRight;
                tf.contentVerticalAlignment = UIControlContentVerticalAlignmentCenter;
                tf.autoresizingMask         = UIViewAutoresizingFlexibleWidth;
                tf.tag                      = 200;
                [cell.contentView addSubview:tf];
                self.registeredAddressField = tf;

                CGRect b = cell.contentView.bounds;
                tf.frame = CGRectMake(90.0f, 0, b.size.width - 106.0f, b.size.height);

            } else {
                NSString *addr = [prof objectForKey:@"server_address"];
                NSDictionary *dns = [dm cachedDNSForServerAddress:addr
                                                     profileIndex:self.profileIndex];
                BOOL wantsPort = (indexPath.row == 2);

                cell.textLabel.text = wantsPort ? @"Port" : @"Last Known IP";

                NSString *value = wantsPort ? [dns[@"port"] description] : dns[@"ip"];
                cell.detailTextLabel.text = ([value length] > 0) ? value : @"Not resolved yet";
            }
            break;
        }
        case SectionDevice: {
            if (indexPath.row == 0) {
                cell.textLabel.text = @"Device ID";
                cell.detailTextLabel.text = [prof objectForKey:@"device_address"] ?: @"None";
                cell.detailTextLabel.adjustsFontSizeToFitWidth = YES;
                cell.detailTextLabel.minimumFontSize = 8.0f;
            } else {
                cell.textLabel.text = @"Registration Cert";
                if (self.regIdentitySaveInFlight) {
                    cell.detailTextLabel.text = @"Importing\xe2\x80\xa6";
                } else {
                    cell.detailTextLabel.text =
                        [prof objectForKey:@"registration_identity"] ? @"Imported" : @"None";
                    cell.accessoryType  = UITableViewCellAccessoryDisclosureIndicator;
                    cell.selectionStyle = UITableViewCellSelectionStyleBlue;
                }
            }
            break;
        }
        case SectionActions: {
            cell.textLabel.text      = self.unregisterInFlight ? @"Unregistering\xe2\x80\xa6" : @"Unregister Device";
            cell.textLabel.textColor = self.unregisterInFlight
                ? SNSecondaryLabelColor([UIColor grayColor])
                : SNSystemRedColor([UIColor redColor]);
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

    if (indexPath.section == SectionDevice && indexPath.row == 1 &&
        ![self _deviceIsRegistered] && !self.regIdentitySaveInFlight) {
        [self.view endEditing:YES];
        self.importingRegIdentity = YES;

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
    if (self.importingRegIdentity) {
        self.importingRegIdentity = NO;
        NSString *capturedPath = [[path copy] autorelease];
        [SNAlert presentTitle:@"Confirm Registration Cert"
                      message:[NSString stringWithFormat:
                               @"Import \"%@\" as this profile's registration certificate?",
                               [path lastPathComponent]]
                 cancelButton:@"Cancel"
                confirmButton:@"Import"
                  destructive:NO
                         from:picker
                    onConfirm:^{
            [self _importRegistrationIdentityFromPath:capturedPath];
        }];
        return;
    }

    NSString *filename  = [path lastPathComponent];
    NSString *message   = [NSString stringWithFormat:
                           @"Import \"%@\" as the server certificate for %@?",
                           filename, self.pendingServerAddress];

    NSString *capturedAddress = [[self.pendingServerAddress copy] autorelease];
    NSString *capturedPath    = [[path copy] autorelease];
    [SNAlert presentTitle:@"Confirm Certificate"
                  message:message
             cancelButton:@"Cancel"
            confirmButton:@"Import"
              destructive:NO
                     from:picker
                onConfirm:^{
        [self _confirmImportFromPath:capturedPath serverAddress:capturedAddress];
    }];
}

- (void)_importRegistrationIdentityFromPath:(NSString *)path {
    if (self.regIdentitySaveInFlight) return;
    self.regIdentitySaveInFlight = YES;

    if (self.navigationController.topViewController != self) {
        [self.navigationController popToViewController:self animated:YES];
    }
    [self.tableView reloadData];

    NSString *pathCopy = [[path copy] autorelease];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
        NSString *pem = [[NSString alloc] initWithContentsOfFile:pathCopy
                                                        encoding:NSUTF8StringEncoding
                                                           error:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
            if ([pem length] == 0) {
                self.regIdentitySaveInFlight = NO;
                [self.tableView reloadData];
                [SNAlert presentMessage:@"Could not read the selected .pem file."
                                  title:@"Import Failed"
                                   from:self];
                [pem release];
                return;
            }
            [SNChannelGateway setRegistrationIdentityAtIndex:self.profileIndex
                                                 identityPEM:pem
                                                  completion:^(BOOL ok, NSString *message) {
                self.regIdentitySaveInFlight = NO;
                [self.tableView reloadData];
                if (!ok) {
                    [SNAlert presentMessage:message title:@"Import Failed" from:self];
                }
            }];
            [pem release];
        });
        [pool drain];
    });
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
            [SNAlert presentMessage:errorMessage title:@"Auto-Fetch Failed" from:self];
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

    NSString *capturedAddress = serverAddress;
    NSString *capturedPEM     = pem;
    [SNAlert presentTitle:@"Confirm Certificate"
                  message:message
             cancelButton:@"Cancel"
            confirmButton:@"Install"
              destructive:NO
                     from:self
                onConfirm:^{
        [self _commitInstallFetchedPEM:capturedPEM serverAddress:capturedAddress];
    }];
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
                    [SNAlert presentMessage:@"Could not read the selected .pem file. Make sure the file is a valid PEM certificate."
                                      title:@"Import Failed"
                                       from:self];
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

    self.profileSaveActivity = [SNDeferredActivity begunActivityWithShowBlock:^{
        self.profileSaveInFlight = YES;
        [self.tableView reloadData];
    } hideBlock:^{
        self.profileSaveInFlight = NO;
        [self.tableView reloadData];
    }];
    return YES;
}

- (void)_finishProfileSaveActivityWithCompletion:(void (^)(void))completion {
    [self.profileSaveActivity finishWithCompletion:^{
        self.profileSaveRequestInFlight = NO;
        self.profileSaveActivity = nil;
        self.profileSaveWizardRow = -1;
        self.profileSaveStatusText = nil;
        [self.navigationItem setHidesBackButton:NO animated:YES];
        self.tableView.allowsSelection = YES;
        if (completion) completion();
    }];
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
                [SNAlert presentMessage:message ?: @"The daemon did not respond."
                                  title:failureTitle ?: @"Save Failed"
                                   from:self];
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

    self.unregisterActivity = [SNDeferredActivity begunActivityWithShowBlock:^{
        self.unregisterInFlight = YES;
        [self.tableView reloadData];
    } hideBlock:^{
        self.unregisterInFlight = NO;
        [self.tableView reloadData];
    }];

    NSInteger idx = self.profileIndex;
    [SNChannelGateway deleteProfileAtIndex:idx
                                completion:^(BOOL ok, NSString *message) {
        [self.unregisterActivity finishWithCompletion:^{
            self.unregisterRequestInFlight = NO;
            self.unregisterActivity = nil;
            [self.navigationItem setHidesBackButton:NO animated:YES];
            self.tableView.allowsSelection = YES;

            if (!ok) {
                [SNAlert presentMessage:message ?: @"The daemon did not respond."
                                  title:@"Could Not Unregister"
                                   from:self];
                return;
            }

            [self.navigationController popViewControllerAnimated:YES];
        }];
    }];
}

- (void)_showUnregisterConfirmation {
    [SNAlert presentTitle:@"Unregister?"
                  message:@"This will disable the daemon and delete your cryptographic keys. The server will be disconnected."
             cancelButton:@"Cancel"
            confirmButton:@"Unregister"
              destructive:YES
                     from:self
                onConfirm:^{
        [self _performUnregister];
    }];
}

- (void)dealloc {
    [_pendingServerAddress release];
    [_profileSaveStatusText release];
    [_unregisterActivity release];
    [_profileSaveActivity release];

    [super dealloc];
}

@end
