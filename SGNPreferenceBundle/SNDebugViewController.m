#import "SNDebugViewController.h"
#import "SNDataManager.h"
#import "SNLogTailViewController.h"
#import "SNChannelGateway.h"
#import "SNDeferredActivity.h"
#include <spawn.h>
#include <sys/wait.h>
#import <mach/mach.h>
#import <mach/message.h>
#include <bootstrap.h>
#import "SNAlert.h"
#import "SNInterfaceColors.h"

extern char **environ;

typedef enum {
    SectionManualReg,
    SectionSavedTokens,
    SectionStats,
    SectionLogs,
    SectionDaemon,
    SectionCount
} DebugSection;

@interface SNDebugViewController () {
    NSString       *_appCount;
    NSString       *_dbSize;
    NSMutableArray *_savedApps;   // @[ @{@"bundleID", @"token", @"routingKey"} ]
    UITextField    *_manualBundleIDParams;
    NSMutableSet   *_pendingDeletionBundleIDs;
    NSMutableSet   *_deletingBundleIDs;
    SNDeferredActivity *_deleteActivity;
}
@end

@implementation SNDebugViewController

- (void)setRootController:(id)controller {}
- (void)setParentController:(id)controller {}
- (void)setSpecifier:(id)specifier {}
- (void)willResignActive {}
- (void)willBecomeActive {}

- (id)init {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        self.title = @"Debug Tools";
        _savedApps = [[NSMutableArray alloc] init];
        _pendingDeletionBundleIDs = [[NSMutableSet alloc] init];
        _deletingBundleIDs = [[NSMutableSet alloc] init];
    }
    return self;
}

- (BOOL)_isDeleting {
    return (_deletingBundleIDs.count > 0 || _pendingDeletionBundleIDs.count > 0);
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

    NSString *pathCopy = [path copy];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        pid_t pid = 0;
        const char *cpath = [pathCopy fileSystemRepresentation];
        char *const args[] = { (char *)cpath, NULL };
        if (posix_spawn(&pid, cpath, NULL, NULL, args, environ) == 0) {
            waitpid(pid, NULL, 0);
        }
        [pathCopy release];
    });
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
                cell.textLabel.textColor = SNSystemBlueColor([UIColor colorWithRed:0.0 green:0.478 blue:1.0 alpha:1.0]);
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
            NSString *bundleId = app[@"bundleID"];
            cell.textLabel.text = bundleId;
            NSString *hex = [[SNDataManager shared] hexStringFromData:app[@"token"]];
            NSUInteger truncLen = MIN((NSUInteger)16, [hex length]);
            cell.detailTextLabel.text = [NSString stringWithFormat:@"Token: %@...",
                                         [hex substringToIndex:truncLen]];
            cell.detailTextLabel.textColor = SNSecondaryLabelColor([UIColor grayColor]);

            if ([_deletingBundleIDs containsObject:bundleId]) {
                UIActivityIndicatorView *spin = [[UIActivityIndicatorView alloc]
                    initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
                [spin startAnimating];
                cell.accessoryView = spin;
                [spin release];
                cell.selectionStyle = UITableViewCellSelectionStyleNone;
                cell.accessoryType  = UITableViewCellAccessoryNone;
            } else {
                cell.accessoryView = nil;
                cell.selectionStyle = UITableViewCellSelectionStyleBlue;
                cell.accessoryType  = UITableViewCellAccessoryDisclosureIndicator;
            }
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
        cell.detailTextLabel.textColor = SNSecondaryLabelColor([UIColor darkGrayColor]);
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
        cell.textLabel.textColor = SNLabelColor([UIColor blackColor]);
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    } else if (indexPath.section == SectionDaemon) {
        cell.textLabel.text = @"Restart Daemon";
        cell.textLabel.textAlignment = NSTextAlignmentCenter;
        cell.textLabel.textColor = SNSystemBlueColor([UIColor colorWithRed:0.0 green:0.478 blue:1.0 alpha:1.0]);
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

            NSString *bidCopy = [bundleID copy];
            [SNChannelGateway registerInputAppForBundleId:bidCopy
                                               completion:^(BOOL ok, NSString *message) {
                if (ok) {
                    [self showAlert:@"Registered"
                            message:[NSString stringWithFormat:
                                @"Skyglow registered '%@' and saved its provider state.",
                                bidCopy]];
                } else {
                    [self showAlert:@"Registration Failed"
                            message:message ?: @"SpringBoard did not respond."];
                }
                [bidCopy release];
                [self loadStats];
                [self.tableView reloadData];
            }];
            _manualBundleIDParams.text = @"";

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
    }
}

- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath {
    if ([self _isDeleting]) return NO;
    return (indexPath.section == SectionSavedTokens && _savedApps.count > 0);
}

- (UITableViewCellEditingStyle)tableView:(UITableView *)tableView editingStyleForRowAtIndexPath:(NSIndexPath *)indexPath {
    if ([self _isDeleting]) return UITableViewCellEditingStyleNone;
    if (indexPath.section != SectionSavedTokens || _savedApps.count == 0) return UITableViewCellEditingStyleNone;
    return UITableViewCellEditingStyleDelete;
}

- (void)tableView:(UITableView *)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle
                                            forRowAtIndexPath:(NSIndexPath *)indexPath {
    if (editingStyle != UITableViewCellEditingStyleDelete) return;
    if (indexPath.section != SectionSavedTokens) return;
    if (indexPath.row >= (NSInteger)_savedApps.count) return;
    if ([self _isDeleting]) return;

    NSDictionary *app = _savedApps[indexPath.row];
    NSString *bundleId = [[app[@"bundleID"] copy] autorelease];
    if (![bundleId isKindOfClass:[NSString class]] || bundleId.length == 0) return;  /* addObject:nil would throw */
    NSIndexPath *capturedPath = [[indexPath copy] autorelease];

    [tableView setEditing:NO animated:YES];

    [_pendingDeletionBundleIDs addObject:bundleId];
    self.navigationItem.hidesBackButton = YES;

    [_deleteActivity release];
    _deleteActivity = [[SNDeferredActivity alloc] initWithShowBlock:^{
        if (![_pendingDeletionBundleIDs containsObject:bundleId]) return;
        [_pendingDeletionBundleIDs removeObject:bundleId];
        [_deletingBundleIDs addObject:bundleId];
        if (capturedPath.row < (NSInteger)_savedApps.count &&
            [_savedApps[capturedPath.row][@"bundleID"] isEqualToString:bundleId]) {
            [self.tableView reloadRowsAtIndexPaths:@[capturedPath]
                                  withRowAnimation:UITableViewRowAnimationNone];
        }
    } hideBlock:^{
        [_deletingBundleIDs removeObject:bundleId];
        if (capturedPath.row < (NSInteger)_savedApps.count) {
            [self.tableView reloadRowsAtIndexPaths:@[capturedPath]
                                  withRowAnimation:UITableViewRowAnimationNone];
        }
    }];
    [_deleteActivity begin];

    [SNChannelGateway deleteAppForBundleId:bundleId
                                completion:^(BOOL ok, NSString *message) {
        SNDeferredActivity *activity = [_deleteActivity retain];
        [activity finishWithCompletion:^{
            [_pendingDeletionBundleIDs removeObject:bundleId];
            [_deletingBundleIDs removeObject:bundleId];
            [_deleteActivity release];
            _deleteActivity = nil;
            self.navigationItem.hidesBackButton = [self _isDeleting];

            if (!ok) {
                if (capturedPath.row < (NSInteger)_savedApps.count) {
                    [self.tableView reloadRowsAtIndexPaths:@[capturedPath]
                                          withRowAnimation:UITableViewRowAnimationNone];
                }
                [self showAlert:@"Could Not Delete Token"
                        message:message ?: @"The daemon did not respond."];
                return;
            }

            /* Success: refresh table + the saved-tokens count cell in Stats. */
            [self loadStats];
            [self.tableView reloadData];
        }];
        [activity release];
    }];
}

- (void)showAlert:(NSString *)title message:(NSString *)msg {
    [SNAlert presentMessage:msg title:title from:self];
}

- (void)dealloc {
    [_appCount release];
    [_dbSize release];
    [_savedApps release];
    [_pendingDeletionBundleIDs release];
    [_deletingBundleIDs release];
    [_deleteActivity release];
    [super dealloc];
}

@end
