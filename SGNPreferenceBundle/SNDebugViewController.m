#import "SNDebugViewController.h"
#import "SNDataManager.h"
#import "SNLogTailViewController.h"
#import "SNChannelGateway.h"
#include <spawn.h>
#include <sys/wait.h>
#import <mach/mach.h>
#import <mach/message.h>
#include <bootstrap.h>
#import <objc/runtime.h>
#import <objc/message.h>

extern char **environ;

typedef enum {
    SectionManualReg,
    SectionSavedTokens,
    SectionStats,
    SectionLogs,
    SectionDaemon,
    SectionMaintenance,
    SectionCount
} DebugSection;

@interface SNDebugViewController () {
    NSString       *_appCount;
    NSString       *_dbSize;
    NSMutableArray *_savedApps;   // @[ @{@"bundleID", @"token", @"routingKey"} ]
    UITextField    *_manualBundleIDParams;
}
@end

@implementation SNDebugViewController

- (void)setRootController:(id)controller {}
- (void)setParentController:(id)controller {}
- (void)setSpecifier:(id)specifier {}

- (id)init {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        self.title = @"Debug Tools";
        _savedApps = [[NSMutableArray alloc] init];
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    [self loadStats];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self loadStats];
    [self.tableView reloadData];
}

- (void)loadStats {
    SNDataManager *dm = [SNDataManager shared];

    [_appCount release];
    _appCount = [[NSString stringWithFormat:@"%ld", (long)[dm registeredTokenCount]] retain];

    unsigned long long size = [dm dbFileSize];
    [_dbSize release];
    _dbSize = [(size > 0 ? [NSString stringWithFormat:@"%.1f KB", size / 1024.0] : @"0 B") retain];

    [_savedApps removeAllObjects];
    [_savedApps addObjectsFromArray:[dm allRegisteredTokens]];
}

- (void)reloadDaemon {
    NSString *path = [[NSBundle bundleForClass:[self class]]
                      pathForResource:@"sndrestart" ofType:nil];
    if (!path) {
        [self showAlert:@"Error" message:@"sndrestart binary not found in bundle."];
        return;
    }
    pid_t pid = 0;
    const char *cpath = [path fileSystemRepresentation];
    char *const args[] = { (char *)cpath, NULL };
    if (posix_spawn(&pid, cpath, NULL, NULL, args, environ) == 0) {
        waitpid(pid, NULL, 0);
    }
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return SectionCount;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    switch ((DebugSection)section) {
        case SectionManualReg:   return 2;
        case SectionSavedTokens: return _savedApps.count > 0 ? _savedApps.count : 1;
        case SectionStats:       return 2;
        case SectionLogs:        return 1;
        case SectionDaemon:      return 1;
        case SectionMaintenance: return 2;
        default: return 0;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    switch ((DebugSection)section) {
        case SectionManualReg:   return @"Manual Registration & Testing";
        case SectionSavedTokens: return @"Saved Tokens";
        case SectionStats:       return @"Database Statistics";
        case SectionLogs:        return @"Logs";
        case SectionDaemon:      return @"Daemon";
        case SectionMaintenance: return @"Maintenance";
        default: return nil;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == SectionSavedTokens && _savedApps.count > 0)
        return @"Tap to copy token. Swipe to delete.";
    if (section == SectionLogs)
        return @"Live tail of /var/log/skyglow.log.";
    if (section == SectionDaemon)
        return @"Stops and restarts the background daemon process.";
    return nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *buttonCellID = @"ButtonCell";
    static NSString *valueCellID  = @"ValueCell";
    static NSString *tokenCellID  = @"TokenCell";
    static NSString *inputCellID  = @"InputCell";

    if (indexPath.section == SectionManualReg) {
        if (indexPath.row == 0) {
            UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:inputCellID];
            if (!cell) {
                cell = [[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                              reuseIdentifier:inputCellID] autorelease];
                CGFloat cellH = 44.0;
                UITextField *tf = [[UITextField alloc] initWithFrame:CGRectMake(15, 0, 290, cellH)];
                tf.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
                tf.contentVerticalAlignment = UIControlContentVerticalAlignmentCenter;
                tf.placeholder = @"com.example.app";
                tf.textAlignment = NSTextAlignmentCenter;
                tf.autocorrectionType = UITextAutocorrectionTypeNo;
                tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
                tf.returnKeyType = UIReturnKeyDone;
                [cell.contentView addSubview:tf];

                _manualBundleIDParams = tf;
                [tf release];
            }
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
            return cell;
        } else {
            UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:buttonCellID];
            if (!cell) {
                cell = [[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                              reuseIdentifier:buttonCellID] autorelease];
                cell.textLabel.textAlignment = NSTextAlignmentCenter;
            }
            cell.selectionStyle = UITableViewCellSelectionStyleBlue;
            
            if (indexPath.row == 1) {
                cell.textLabel.text = @"Register Bundle ID";
                cell.textLabel.textColor = [UIColor colorWithRed:0.0 green:0.478 blue:1.0 alpha:1.0];
            }
            
            return cell;
        }
    }
    
    if (indexPath.section == SectionSavedTokens) {
        UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:tokenCellID];
        if (!cell) {
            cell = [[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                          reuseIdentifier:tokenCellID] autorelease];
        }
        
        if (_savedApps.count == 0) {
            cell.textLabel.text = @"No tokens found";
            cell.detailTextLabel.text = nil;
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
            cell.accessoryType  = UITableViewCellAccessoryNone;
        } else {
            NSDictionary *app = _savedApps[indexPath.row];
            cell.textLabel.text = app[@"bundleID"];
            NSString *hex = [[SNDataManager shared] hexStringFromData:app[@"token"]];
            NSUInteger truncLen = MIN((NSUInteger)16, [hex length]);
            cell.detailTextLabel.text = [NSString stringWithFormat:@"Token: %@...",
                                         [hex substringToIndex:truncLen]];
            cell.detailTextLabel.textColor = [UIColor grayColor];
            cell.selectionStyle = UITableViewCellSelectionStyleBlue;
            cell.accessoryType  = UITableViewCellAccessoryDisclosureIndicator;
        }
        return cell;
    }
    
    if (indexPath.section == SectionStats) {
        UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:valueCellID];
        if (!cell) {
            cell = [[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1
                                          reuseIdentifier:valueCellID] autorelease];
        }
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        cell.detailTextLabel.textColor = [UIColor darkGrayColor];
        if (indexPath.row == 0) {
            cell.textLabel.text = @"Registered Apps";
            cell.detailTextLabel.text = _appCount;
        } else {
            cell.textLabel.text = @"DB Size";
            cell.detailTextLabel.text = _dbSize;
        }
        return cell;
    }
    
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:buttonCellID];
    if (!cell) {
        cell = [[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                      reuseIdentifier:buttonCellID] autorelease];
        cell.textLabel.textAlignment = NSTextAlignmentCenter;
    }
    
    cell.selectionStyle = UITableViewCellSelectionStyleBlue;
    cell.accessoryType  = UITableViewCellAccessoryNone;

    if (indexPath.section == SectionLogs) {
        cell.textLabel.text = @"View Logs";
        cell.textLabel.textAlignment = NSTextAlignmentLeft;
        cell.textLabel.textColor = [UIColor blackColor];
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    } else if (indexPath.section == SectionDaemon) {
        cell.textLabel.text = @"Restart Daemon";
        cell.textLabel.textAlignment = NSTextAlignmentCenter;
        cell.textLabel.textColor = [UIColor colorWithRed:0.0 green:0.478 blue:1.0 alpha:1.0];
    } else if (indexPath.section == SectionMaintenance) {
        cell.textLabel.textAlignment = NSTextAlignmentCenter;
        if (indexPath.row == 0) {
            cell.textLabel.text = @"Clear DNS Cache";
            cell.textLabel.textColor = [UIColor redColor];
        } else {
            cell.textLabel.text = @"Clear All Tokens";
            cell.textLabel.textColor = [UIColor redColor];
        }
    }
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];

    if (indexPath.section == SectionManualReg) {
        [_manualBundleIDParams resignFirstResponder];
        
        if (indexPath.row == 1) {
            NSString *bundleID = _manualBundleIDParams.text;
            if (bundleID.length == 0) {
                [self showAlert:@"Error" message:@"Please enter a valid Bundle ID."];
                return;
            }

            [[SNDataManager shared] setAppStatusValue:YES forBundleId:bundleID];

            [SNChannelGateway postRegisterInputAppForBundleId:bundleID];

            [self showAlert:@"Request Sent"
                    message:[NSString stringWithFormat:@"Registration request for '%@' sent to SpringBoard.", bundleID]];
            _manualBundleIDParams.text = @"";

            [self loadStats];
            [self.tableView reloadData];

        } else if (indexPath.row == 2) {

            [SNChannelGateway postTestInject];

            [self showAlert:@"Test Triggered"
                    message:@"Test-inject request sent to the daemon."];
        }
        
    } else if (indexPath.section == SectionSavedTokens && _savedApps.count > 0) {
        NSDictionary *app = _savedApps[indexPath.row];
        NSString *hex = [[SNDataManager shared] hexStringFromData:app[@"token"]];
        [UIPasteboard generalPasteboard].string = hex;
        [self showAlert:@"Token Copied"
                message:[NSString stringWithFormat:@"Bundle: %@\n\nHex:\n%@",
                         app[@"bundleID"], hex]];

    } else if (indexPath.section == SectionLogs) {
        SNLogTailViewController *vc = [[SNLogTailViewController alloc] init];
        [self.navigationController pushViewController:vc animated:YES];
        [vc release];

    } else if (indexPath.section == SectionDaemon) {
        [self reloadDaemon];
        [self showAlert:@"Done" message:@"Daemon restarted."];
        
    } else if (indexPath.section == SectionMaintenance) {
        if (indexPath.row == 0) {
            [[SNDataManager shared] clearDNSCache];
            [self showAlert:@"Done" message:@"DNS cache cleared."];
        } else {
            [[SNDataManager shared] clearAllTokens];
            [self loadStats];
            [self.tableView reloadData];
            [self showAlert:@"Done" message:@"All tokens cleared."];
        }
    }
}

- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath {
    return (indexPath.section == SectionSavedTokens && _savedApps.count > 0);
}

- (void)tableView:(UITableView *)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle
                                            forRowAtIndexPath:(NSIndexPath *)indexPath {
    if (editingStyle != UITableViewCellEditingStyleDelete) return;
    if (indexPath.section != SectionSavedTokens) return;
    if (indexPath.row >= (NSInteger)_savedApps.count) return;
    
    NSDictionary *app = _savedApps[indexPath.row];
    NSString *bundleId = app[@"bundleID"];
    
    [[SNDataManager shared] removeAppFromDatabase:bundleId];
    [_savedApps removeObjectAtIndex:indexPath.row];
    
    if (_savedApps.count == 0) {
        [tableView reloadSections:[NSIndexSet indexSetWithIndex:SectionSavedTokens]
                 withRowAnimation:UITableViewRowAnimationAutomatic];
    } else {
        [tableView deleteRowsAtIndexPaths:@[indexPath]
                         withRowAnimation:UITableViewRowAnimationAutomatic];
    }
    
    [_appCount release];
    _appCount = [[NSString stringWithFormat:@"%lu", (unsigned long)_savedApps.count] retain];
    [tableView reloadSections:[NSIndexSet indexSetWithIndex:SectionStats]
             withRowAnimation:UITableViewRowAnimationNone];
}

- (void)showAlert:(NSString *)title message:(NSString *)msg {
    Class alertControllerClass = NSClassFromString(@"UIAlertController");
    
    if (alertControllerClass) {
        SEL alertCreateSel = NSSelectorFromString(@"alertControllerWithTitle:message:preferredStyle:");
        id (*createAlert)(Class, SEL, id, id, NSInteger) = (id (*)(Class, SEL, id, id, NSInteger))objc_msgSend;
        id alert = createAlert(alertControllerClass, alertCreateSel, title, msg, 1);
        
        Class alertActionClass = NSClassFromString(@"UIAlertAction");
        SEL actionCreateSel = NSSelectorFromString(@"actionWithTitle:style:handler:");
        id (*createAction)(Class, SEL, id, NSInteger, id) = (id (*)(Class, SEL, id, NSInteger, id))objc_msgSend;
        id action = createAction(alertActionClass, actionCreateSel, @"OK", 0, nil);
        
        SEL addActionSel = NSSelectorFromString(@"addAction:");
        void (*addAction)(id, SEL, id) = (void (*)(id, SEL, id))objc_msgSend;
        addAction(alert, addActionSel, action);
        
        SEL presentSel = NSSelectorFromString(@"presentViewController:animated:completion:");
        void (*present)(id, SEL, id, BOOL, id) = (void (*)(id, SEL, id, BOOL, id))objc_msgSend;
        present(self, presentSel, alert, YES, nil);
        
    } else {
        UIAlertView *av = [[UIAlertView alloc] initWithTitle:title
                                                     message:msg
                                                    delegate:nil
                                           cancelButtonTitle:@"OK"
                                           otherButtonTitles:nil];
        [av show];
        [av release];
    }
}

- (void)dealloc {
    [_appCount release];
    [_dbSize release];
    [_savedApps release];
    [super dealloc];
}

@end
