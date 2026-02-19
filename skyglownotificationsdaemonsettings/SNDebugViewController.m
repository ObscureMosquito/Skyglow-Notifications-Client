#import "SNDebugViewController.h"
#import "SNDataManager.h"
#include <spawn.h>
#include <sys/wait.h>
#import <mach/mach.h>
#import <mach/message.h>
#include <bootstrap.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import "../TweakMachMessages.h"

extern char **environ;

typedef enum {
    SectionManualReg,
    SectionSavedTokens,
    SectionStats,
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
    
    _appCount = [NSString stringWithFormat:@"%ld", (long)[dm registeredTokenCount]];
    
    unsigned long long size = [dm dbFileSize];
    _dbSize = size > 0 ? [NSString stringWithFormat:@"%.1f KB", size / 1024.0] : @"0 B";
    
    [_savedApps removeAllObjects];
    [_savedApps addObjectsFromArray:[dm allRegisteredTokens]];
}

// ──────────────────────────────────────────────
// Daemon restart helper
// ──────────────────────────────────────────────

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

// ──────────────────────────────────────────────
// TableView DataSource
// ──────────────────────────────────────────────

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return SectionCount;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    switch ((DebugSection)section) {
        case SectionManualReg:   return 3; // TextField + Register Button + Test Notif Button
        case SectionSavedTokens: return _savedApps.count > 0 ? _savedApps.count : 1;
        case SectionStats:       return 2;
        case SectionDaemon:      return 1;
        case SectionMaintenance: return 2; // Clear DNS + Clear All Tokens
        default: return 0;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    switch ((DebugSection)section) {
        case SectionManualReg:   return @"Manual Registration & Testing";
        case SectionSavedTokens: return @"Saved Tokens";
        case SectionStats:       return @"Database Statistics";
        case SectionDaemon:      return @"Daemon";
        case SectionMaintenance: return @"Maintenance";
        default: return nil;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == SectionSavedTokens && _savedApps.count > 0)
        return @"Tap to copy token. Swipe to delete.";
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
                cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                              reuseIdentifier:inputCellID];
                UITextField *tf = [[UITextField alloc] initWithFrame:CGRectInset(cell.contentView.bounds, 15, 0)];
                tf.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
                tf.placeholder = @"com.example.app";
                tf.textAlignment = NSTextAlignmentCenter;
                tf.autocorrectionType = UITextAutocorrectionTypeNo;
                tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
                tf.returnKeyType = UIReturnKeyDone;
                [cell.contentView addSubview:tf];
                _manualBundleIDParams = tf;
            }
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
            return cell;
        } else {
            UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:buttonCellID];
            if (!cell) {
                cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                              reuseIdentifier:buttonCellID];
                cell.textLabel.textAlignment = NSTextAlignmentCenter;
            }
            cell.selectionStyle = UITableViewCellSelectionStyleBlue; // Changed from Default to Blue
            
            if (indexPath.row == 1) {
                cell.textLabel.text = @"Register Bundle ID";
                // Standard iOS blue
                cell.textLabel.textColor = [UIColor colorWithRed:0.0 green:0.478 blue:1.0 alpha:1.0];
            } else if (indexPath.row == 2) { 
                // Only configure visuals here!
                cell.textLabel.text = @"Send Test Notification";
                if ([UIColor respondsToSelector:@selector(systemPurpleColor)]) {
                    cell.textLabel.textColor = [UIColor performSelector:@selector(systemPurpleColor)];
                } else {
                    cell.textLabel.textColor = [UIColor purpleColor];
                }
            }
            
            return cell;
        }
    }
    
    if (indexPath.section == SectionSavedTokens) {
        UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:tokenCellID];
        if (!cell) {
            cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                          reuseIdentifier:tokenCellID];
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
            cell.selectionStyle = UITableViewCellSelectionStyleBlue; // Changed from Default to Blue
            cell.accessoryType  = UITableViewCellAccessoryDisclosureIndicator;
        }
        return cell;
    }
    
    if (indexPath.section == SectionStats) {
        UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:valueCellID];
        if (!cell) {
            cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1
                                          reuseIdentifier:valueCellID];
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
    
    // Daemon + Maintenance sections use button-style cells
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:buttonCellID];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                      reuseIdentifier:buttonCellID];
        cell.textLabel.textAlignment = NSTextAlignmentCenter;
    }
    
    cell.selectionStyle = UITableViewCellSelectionStyleBlue; // Changed from Default to Blue
    cell.accessoryType  = UITableViewCellAccessoryNone;
    
    if (indexPath.section == SectionDaemon) {
        cell.textLabel.text = @"Restart Daemon";
        cell.textLabel.textColor = [UIColor colorWithRed:0.0 green:0.478 blue:1.0 alpha:1.0];
    } else if (indexPath.section == SectionMaintenance) {
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

// ──────────────────────────────────────────────
// TableView Delegate
// ──────────────────────────────────────────────

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];

    if (indexPath.section == SectionManualReg) {
        [_manualBundleIDParams resignFirstResponder]; // Dismiss keyboard if open
        
        if (indexPath.row == 1) { // Register Button
            NSString *bundleID = _manualBundleIDParams.text;
            if (bundleID.length == 0) {
                [self showAlert:@"Error" message:@"Please enter a valid Bundle ID."];
                return;
            }

            [[SNDataManager shared] setAppStatusValue:YES forBundleId:bundleID];
            
            NSDictionary *prefs = [[NSUserDefaults standardUserDefaults] persistentDomainForName:@"com.skyglow.sndp"] ?: @{};
            NSMutableDictionary *mutablePrefs = [prefs mutableCopy];
            [mutablePrefs setObject:bundleID forKey:@"lastRegisteredApp"];
            [[NSUserDefaults standardUserDefaults] setPersistentDomain:mutablePrefs forName:@"com.skyglow.sndp"];
            [[NSUserDefaults standardUserDefaults] synchronize];

            CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                                 CFSTR("com.skyglow.sgn.registerInputApp"),
                                                 NULL, NULL, TRUE);

            [self showAlert:@"Request Sent"
                    message:[NSString stringWithFormat:@"Registration request for '%@' sent to SpringBoard.", bundleID]];
            _manualBundleIDParams.text = @"";
            
        } else if (indexPath.row == 2) { // Test Notification Button
            
            NSLog(@"[SGN-Settings] Sending Darwin signal: com.skyglow.test-inject");
            
            // Fire the test notification Darwin event we catch in SpringBoard
            CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                                 CFSTR("com.skyglow.test-inject"),
                                                 NULL, NULL, TRUE);
                                                 
            [self showAlert:@"Test Triggered"
                    message:@"Sent signal 'com.skyglow.test-inject' to SpringBoard."];
        }
        
    } else if (indexPath.section == SectionSavedTokens && _savedApps.count > 0) {
        NSDictionary *app = _savedApps[indexPath.row];
        NSString *hex = [[SNDataManager shared] hexStringFromData:app[@"token"]];
        [UIPasteboard generalPasteboard].string = hex;
        [self showAlert:@"Token Copied"
                message:[NSString stringWithFormat:@"Bundle: %@\n\nHex:\n%@",
                         app[@"bundleID"], hex]];
                         
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

// ──────────────────────────────────────────────
// Swipe-to-delete tokens
// ──────────────────────────────────────────────

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
        // Reload section to show "No tokens found" placeholder
        [tableView reloadSections:[NSIndexSet indexSetWithIndex:SectionSavedTokens]
                 withRowAnimation:UITableViewRowAnimationAutomatic];
    } else {
        [tableView deleteRowsAtIndexPaths:@[indexPath]
                         withRowAnimation:UITableViewRowAnimationAutomatic];
    }
    
    // Refresh stats
    _appCount = [NSString stringWithFormat:@"%lu", (unsigned long)_savedApps.count];
    [tableView reloadSections:[NSIndexSet indexSetWithIndex:SectionStats]
             withRowAnimation:UITableViewRowAnimationNone];
}

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

- (void)showAlert:(NSString *)title message:(NSString *)msg {
    Class alertControllerClass = NSClassFromString(@"UIAlertController");
    
    if (alertControllerClass) {
        // ── iOS 8+ Modern UIAlertController via Runtime ──
        
        // UIAlertControllerStyleAlert = 1
        SEL alertCreateSel = NSSelectorFromString(@"alertControllerWithTitle:message:preferredStyle:");
        id (*createAlert)(Class, SEL, id, id, NSInteger) = (id (*)(Class, SEL, id, id, NSInteger))objc_msgSend;
        id alert = createAlert(alertControllerClass, alertCreateSel, title, msg, 1);
        
        // UIAlertActionStyleDefault = 0
        Class alertActionClass = NSClassFromString(@"UIAlertAction");
        SEL actionCreateSel = NSSelectorFromString(@"actionWithTitle:style:handler:");
        id (*createAction)(Class, SEL, id, NSInteger, id) = (id (*)(Class, SEL, id, NSInteger, id))objc_msgSend;
        id action = createAction(alertActionClass, actionCreateSel, @"OK", 0, nil);
        
        // [alert addAction:action]
        SEL addActionSel = NSSelectorFromString(@"addAction:");
        void (*addAction)(id, SEL, id) = (void (*)(id, SEL, id))objc_msgSend;
        addAction(alert, addActionSel, action);
        
        // [self presentViewController:alert animated:YES completion:nil]
        SEL presentSel = NSSelectorFromString(@"presentViewController:animated:completion:");
        void (*present)(id, SEL, id, BOOL, id) = (void (*)(id, SEL, id, BOOL, id))objc_msgSend;
        present(self, presentSel, alert, YES, nil);
        
    } else {
        // ── Pre-iOS 8 Fallback (UIAlertView) ──
        UIAlertView *av = [[UIAlertView alloc] initWithTitle:title
                                                     message:msg
                                                    delegate:nil
                                           cancelButtonTitle:@"OK"
                                           otherButtonTitles:nil];
        [av show];
    }
}

@end