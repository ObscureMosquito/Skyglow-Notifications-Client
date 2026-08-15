#import "SNProfileWizardViewController.h"
#import "SNPaneHeader.h"
#import "SNDataManager.h"
#import "SNAlert.h"
#import "SNInterfaceColors.h"

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

@interface SNProfileWizardViewController ()
@property (nonatomic, strong) NSString *pendingServerAddress;
@property (nonatomic, assign) BOOL      autoFetchInProgress;
@property (nonatomic, assign) NSInteger profileSaveWizardRow;
@end

@implementation SNProfileWizardViewController

- (id)initWithProfileIndex:(NSInteger)index {
    self = [super initWithProfileIndex:index];
    if (self) {
        _profileSaveWizardRow = -1;
    }
    return self;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    if ([self isRegistered]) {
        [self replaceWithProfileControllerForCurrentState];
        return;
    }
    [self.navigationItem setHidesBackButton:self.profileSaveRequestInFlight animated:NO];
    [self _installTableHeaderView];
    [self.tableView reloadData];
}

- (void)_installTableHeaderView {
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
    arrowLabel.text = @"➔";
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

#pragma mark - Table

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return WizardSectionCount;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return (section == WizardSectionCert) ? WizardCertRowCount : 1;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    switch (section) {
        case WizardSectionServer: return @"Server Address";
        case WizardSectionCert:   return @"Server Setup";
        default: return nil;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    switch (section) {
        case WizardSectionServer:
            return @"Enter the hostname or IP address of your Skyglow notification server.";
        case WizardSectionCert:
            return @"Fetch the certificate automatically, or import a .pem file manually from disk";
        default: return nil;
    }
}

- (CGFloat)tableView:(UITableView *)tableView heightForFooterInSection:(NSInteger)section {
    return [self heightForFooterTitle:
        [self tableView:tableView titleForFooterInSection:section]];
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
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

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];

    if (indexPath.section != WizardSectionCert) return;
    if (self.pendingServerAddress.length == 0 ||
        self.autoFetchInProgress ||
        self.profileSaveRequestInFlight) return;

    [self.view endEditing:YES];

    if (indexPath.row == WizardCertRowAuto) {
        [self _beginAutoFetchCertificate];
    } else {
        [self presentPEMPicker];
    }
}

#pragma mark - Text field

- (void)textFieldDidEndEditing:(UITextField *)textField {
    self.pendingServerAddress = [textField.text stringByTrimmingCharactersInSet:
                                 [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    [self.tableView reloadData];
}

- (BOOL)textField:(UITextField *)textField
        shouldChangeCharactersInRange:(NSRange)range
        replacementString:(NSString *)string {
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
    return YES;
}

#pragma mark - Certificate install

- (void)filePicker:(SFPFilePickerViewController *)picker didSelectFileAtPath:(NSString *)path {
    NSString *message = [NSString stringWithFormat:
                         @"Import \"%@\" as the server certificate for %@?",
                         [path lastPathComponent], self.pendingServerAddress];

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

    [SNAlert presentTitle:@"Confirm Certificate"
                  message:message
             cancelButton:@"Cancel"
            confirmButton:@"Install"
              destructive:NO
                     from:self
                onConfirm:^{
        [self _installPEM:pem serverAddress:serverAddress
               statusText:@"Installing\xe2\x80\xa6"
             failureTitle:@"Install Failed"
                wizardRow:WizardCertRowAuto];
    }];
}

- (void)_confirmImportFromPath:(NSString *)path serverAddress:(NSString *)serverAddress {
    self.profileSaveWizardRow = WizardCertRowManual;
    if (![self beginProfileSaveActivityWithStatusText:@"Importing\xe2\x80\xa6"]) {
        self.profileSaveWizardRow = -1;
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
                [self finishProfileSaveActivityWithCompletion:^{
                    self.profileSaveWizardRow = -1;
                    [SNAlert presentMessage:@"Could not read the selected .pem file. Make sure the file is a valid PEM certificate."
                                      title:@"Import Failed"
                                       from:self];
                }];
                [pemResult release];
                return;
            }

            [self sendProfileSaveWithServerAddress:addressCopy
                                    certificatePEM:pemResult
                                      failureTitle:@"Import Failed"
                                         onSuccess:^{
                [self _completeWizard];
            }];
            [pemResult release];
        });
        [pool release];
    });
}

- (void)_installPEM:(NSString *)pem
      serverAddress:(NSString *)serverAddress
         statusText:(NSString *)statusText
       failureTitle:(NSString *)failureTitle
          wizardRow:(NSInteger)wizardRow {
    self.profileSaveWizardRow = wizardRow;
    if (![self beginProfileSaveActivityWithStatusText:statusText]) {
        self.profileSaveWizardRow = -1;
        return;
    }
    [self sendProfileSaveWithServerAddress:serverAddress
                            certificatePEM:pem
                              failureTitle:failureTitle
                                 onSuccess:^{
        [self _completeWizard];
    }];
}

- (void)_completeWizard {
    self.profileSaveWizardRow = -1;
    if (self.navigationController.topViewController != self) {
        [self.navigationController popToViewController:self animated:NO];
    }
    [self replaceWithProfileControllerForCurrentState];
}

- (void)dealloc {
    [_pendingServerAddress release];
    [super dealloc];
}

@end
