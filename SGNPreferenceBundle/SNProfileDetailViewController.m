#import "SNProfileDetailViewController.h"
#import "SNDataManager.h"
#import "SNChannelGateway.h"
#import "SNDeferredActivity.h"
#import "SNAlert.h"
#import "SNInterfaceColors.h"

typedef enum {
    SectionServer  = 0,
    SectionDevice  = 1,
    SectionActions = 2,
    SectionCount   = 3
} DetailSection;

@interface SNProfileDetailViewController ()
@property (nonatomic, assign) BOOL         unregisterInFlight;
@property (nonatomic, assign) BOOL         unregisterRequestInFlight;
@property (nonatomic, strong) SNDeferredActivity *unregisterActivity;
@property (nonatomic, unsafe_unretained) UITextField *registeredAddressField;
@property (nonatomic, assign) BOOL         importingRegIdentity;
@property (nonatomic, assign) BOOL         regIdentitySaveInFlight;
@end

@implementation SNProfileDetailViewController

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    if (![self isRegistered]) {
        [self replaceWithProfileControllerForCurrentState];
        return;
    }
    self.importingRegIdentity = NO;
    BOOL busy = self.profileSaveRequestInFlight || self.unregisterRequestInFlight;
    [self.navigationItem setHidesBackButton:busy animated:NO];
    self.tableView.tableHeaderView = nil;
    [self.tableView reloadData];
}

- (SNRegistrationStatus)_registrationStatus {
    return [[SNDataManager shared] registrationStatusForProfileAtIndex:self.profileIndex];
}

- (BOOL)_deviceIsRegistered {
    return [self _registrationStatus] == SNRegistrationRegistered;
}

#pragma mark - Table

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return SectionCount;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    switch (section) {
        case SectionServer:  return 3;
        case SectionDevice:  return [self _deviceIsRegistered] ? 1 : 2;
        case SectionActions: return 1;
        default: return 0;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    switch (section) {
        case SectionServer: return @"Server Details";
        case SectionDevice: return @"Identity";
        default: return nil;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == SectionActions)
        return @"Unregistering disables the daemon and deletes your cryptographic keys. App toggles are preserved.";
    return nil;
}

- (UIView *)tableView:(UITableView *)tableView viewForFooterInSection:(NSInteger)section {
    if (section != SectionDevice) return nil;

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
    return [self heightForFooterTitle:
        [self tableView:tableView titleForFooterInSection:section]];
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
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

    if (indexPath.section == SectionDevice && indexPath.row == 1 &&
        ![self _deviceIsRegistered] && !self.regIdentitySaveInFlight) {
        [self.view endEditing:YES];
        self.importingRegIdentity = YES;
        [self presentPEMPicker];
        return;
    }

    if (indexPath.section == SectionActions && indexPath.row == 0) {
        [self _showUnregisterConfirmation];
    }
}

#pragma mark - Text field

- (void)textFieldDidEndEditing:(UITextField *)textField {
    if (textField.tag != 200) return;
    NSString *trimmed = [textField.text stringByTrimmingCharactersInSet:
                         [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSString *current = [[[SNDataManager shared] profileForIndex:self.profileIndex]
                            objectForKey:@"server_address"];
    if (trimmed.length > 0 && ![trimmed isEqualToString:current]) {
        [self _commitServerAddressChange:trimmed];
    } else if (trimmed.length == 0) {
        textField.text = current;
    }
}

- (void)_commitServerAddressChange:(NSString *)newAddress {
    if (![self beginProfileSaveActivityWithStatusText:@"Saving\xe2\x80\xa6"]) return;
    [self sendProfileSaveWithServerAddress:newAddress
                            certificatePEM:nil
                              failureTitle:@"Save Failed"
                                 onSuccess:^{
        self.title = [NSString stringWithFormat:@"Profile %ld", (long)self.profileIndex];
        [self.tableView reloadData];
    }];
}

#pragma mark - Registration identity

- (void)filePicker:(SFPFilePickerViewController *)picker didSelectFileAtPath:(NSString *)path {
    if (!self.importingRegIdentity) return;
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

#pragma mark - Unregister

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

    [SNChannelGateway deleteProfileAtIndex:self.profileIndex
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
    [_unregisterActivity release];
    [super dealloc];
}

@end
