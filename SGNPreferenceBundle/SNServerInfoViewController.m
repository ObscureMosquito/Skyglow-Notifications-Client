#import "SNServerInfoViewController.h"
#import "SNDataManager.h"
#import <objc/runtime.h>
#import <objc/message.h>

typedef enum {
    SectionServer = 0,
    SectionDevice,
    SectionActions,
    SectionCount
} ServerInfoSection;

@interface SNServerInfoViewController () <UIAlertViewDelegate>
@property (nonatomic, strong) id rootController;
@property (nonatomic, strong) id parentController;
@property (nonatomic, strong) id specifier;
@end

@implementation SNServerInfoViewController

- (id)init {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        self.title = @"Registration Info";
    }
    return self;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self.tableView reloadData];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return [[SNDataManager shared] isRegistered] ? SectionCount : 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (![[SNDataManager shared] isRegistered]) return 1; // Only show "Not Registered"
    
    switch (section) {
        case SectionServer:  return 3; // Address, Resolved IP, Port
        case SectionDevice:  return 1; // Device ID
        case SectionActions: return 1; // Unregister Button
        default: return 0;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (![[SNDataManager shared] isRegistered]) return @"Status";
    
    switch (section) {
        case SectionServer:  return @"Server Details";
        case SectionDevice:  return @"Identity";
        default: return nil;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == SectionActions) {
        return @"Unregistering deletes keys and tokens, but preserves your app toggles. New keys will be generated automatically on next connect.";
    }
    return nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *CellId = @"InfoCell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:CellId];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:CellId];
    }
    
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    cell.textLabel.textColor = [UIColor blackColor];
    cell.detailTextLabel.textColor = [UIColor grayColor];
    cell.accessoryType = UITableViewCellAccessoryNone;

    if (![[SNDataManager shared] isRegistered]) {
        cell.textLabel.text = @"Registration";
        cell.detailTextLabel.text = @"Waiting for configuration...";
        return cell;
    }

    SNDataManager *dm = [SNDataManager shared];
    NSDictionary *dns = [dm cachedDNSForServerAddress:[dm serverAddress]];
    
    switch (indexPath.section) {
        case SectionServer: {
            if (indexPath.row == 0) {
                cell.textLabel.text = @"Domain";
                cell.detailTextLabel.text = [dm serverAddress] ?: @"Unknown";
            } else if (indexPath.row == 1) {
                cell.textLabel.text = @"Resolved IP";
                cell.detailTextLabel.text = dns && dns[@"ip"] ? dns[@"ip"] : @"Waiting...";
            } else if (indexPath.row == 2) {
                cell.textLabel.text = @"Port";
                cell.detailTextLabel.text = dns && dns[@"port"] ? [dns[@"port"] description] : @"Waiting...";
            }
            break;
        }
        case SectionDevice: {
            cell.textLabel.text = @"Device ID";
            cell.detailTextLabel.text = [dm deviceAddress] ?: @"None";
            cell.detailTextLabel.adjustsFontSizeToFitWidth = YES;
            cell.detailTextLabel.minimumFontSize = 8.0;
            break;
        }
        case SectionActions: {
            cell.textLabel.text = @"Unregister Device";
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
    
    if (indexPath.section == SectionActions && indexPath.row == 0) {
        Class alertControllerClass = NSClassFromString(@"UIAlertController");
        if (alertControllerClass) {
            SEL alertCreateSel = NSSelectorFromString(@"alertControllerWithTitle:message:preferredStyle:");
            id (*createAlert)(Class, SEL, id, id, NSInteger) = (id (*)(Class, SEL, id, id, NSInteger))objc_msgSend;
            id alert = createAlert(alertControllerClass, alertCreateSel, @"Unregister?", @"This will delete your cryptographic keys and disconnect from the server.", 1);
            
            Class alertActionClass = NSClassFromString(@"UIAlertAction");
            SEL actionCreateSel = NSSelectorFromString(@"actionWithTitle:style:handler:");
            id (*createAction)(Class, SEL, id, NSInteger, id) = (id (*)(Class, SEL, id, NSInteger, id))objc_msgSend;
            
            id cancelAction = createAction(alertActionClass, actionCreateSel, @"Cancel", 1, nil);
            
            void (^unregisterBlock)(id) = ^(id action) {
                [[SNDataManager shared] unregisterDevice];
                [self.navigationController popViewControllerAnimated:YES];
            };
            id unregisterAction = createAction(alertActionClass, actionCreateSel, @"Unregister", 2, unregisterBlock);
            
            SEL addActionSel = NSSelectorFromString(@"addAction:");
            void (*addAction)(id, SEL, id) = (void (*)(id, SEL, id))objc_msgSend;
            addAction(alert, addActionSel, cancelAction);
            addAction(alert, addActionSel, unregisterAction);
            
            SEL presentSel = NSSelectorFromString(@"presentViewController:animated:completion:");
            void (*present)(id, SEL, id, BOOL, id) = (void (*)(id, SEL, id, BOOL, id))objc_msgSend;
            present(self, presentSel, alert, YES, nil);
        } else {
            UIAlertView *av = [[UIAlertView alloc] initWithTitle:@"Unregister?"
                                                         message:@"This will delete your cryptographic keys and disconnect from the server."
                                                        delegate:self
                                               cancelButtonTitle:@"Cancel"
                                               otherButtonTitles:@"Unregister", nil];
            [av show];
        }
    }
}

- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex {
    if (buttonIndex == 1) { // "Unregister"
        [[SNDataManager shared] unregisterDevice];
        [self.navigationController popViewControllerAnimated:YES];
    }
}

@end