#import "SNDebugViewController.h"
#import "SNDataManager.h"
#include <spawn.h>

typedef enum {
    SectionSimulation = 0,
    SectionSavedTokens,
    SectionDaemon,
    SectionStats,
    SectionNetworking,
    SectionCount
} DebugSection;

@interface SNDebugViewController () {
    NSString       *_appCount;
    NSString       *_dbSize;
    NSMutableArray *_savedApps;   // @[ @{@"bundleID", @"token", @"routingKey"} ]
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
// TableView DataSource
// ──────────────────────────────────────────────

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return SectionCount;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    switch ((DebugSection)section) {
        case SectionSimulation:  return 1;
        case SectionSavedTokens: return _savedApps.count > 0 ? _savedApps.count : 1;
        case SectionDaemon:      return 1;
        case SectionStats:       return 2;
        case SectionNetworking:  return 1;
        default: return 0;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    switch ((DebugSection)section) {
        case SectionSimulation:  return @"Simulation";
        case SectionSavedTokens: return @"Saved Tokens";
        case SectionDaemon:      return @"Daemon Health";
        case SectionStats:       return @"Database Statistics";
        case SectionNetworking:  return @"Networking";
        default: return nil;
    }
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *buttonCellID = @"ButtonCell";
    static NSString *valueCellID  = @"ValueCell";
    static NSString *tokenCellID  = @"TokenCell";
    
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
            cell.detailTextLabel.text = [NSString stringWithFormat:@"Token: %@…",
                                         [hex length] > 16 ? [hex substringToIndex:16] : hex];
            cell.detailTextLabel.textColor = [UIColor grayColor];
            cell.selectionStyle = UITableViewCellSelectionStyleBlue;
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
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                      reuseIdentifier:buttonCellID];
        cell.textLabel.textAlignment = NSTextAlignmentCenter;
    }
    
    cell.selectionStyle = UITableViewCellSelectionStyleBlue;
    cell.accessoryType  = UITableViewCellAccessoryNone;
    
    if (indexPath.section == SectionSimulation) {
        cell.textLabel.text = @"Register Dummy App";
        cell.textLabel.textColor = [UIColor colorWithRed:0.0 green:0.478 blue:1.0 alpha:1.0];
    } else if (indexPath.section == SectionDaemon) {
        cell.textLabel.text = @"Test Daemon Connection";
        cell.textLabel.textColor = [UIColor colorWithRed:0.0 green:0.478 blue:1.0 alpha:1.0];
    } else if (indexPath.section == SectionNetworking) {
        cell.textLabel.text = @"Clear DNS Cache";
        cell.textLabel.textColor = [UIColor redColor];
    }
    return cell;
}

// ──────────────────────────────────────────────
// TableView Delegate
// ──────────────────────────────────────────────

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    
    if (indexPath.section == SectionSavedTokens && _savedApps.count > 0) {
        NSDictionary *app = _savedApps[indexPath.row];
        NSString *hex = [[SNDataManager shared] hexStringFromData:app[@"token"]];
        [UIPasteboard generalPasteboard].string = hex;
        [self showAlert:@"Token Copied"
                message:[NSString stringWithFormat:@"Bundle: %@\n\nHex:\n%@",
                         app[@"bundleID"], hex]];
    } else if (indexPath.section == SectionSimulation) {
        [self registerDummyApp];
    } else if (indexPath.section == SectionDaemon) {
        [self testDaemonConnection];
    } else if (indexPath.section == SectionNetworking) {
        [[SNDataManager shared] clearDNSCache];
        [self showAlert:@"Success" message:@"DNS cache cleared."];
    }
}

// ──────────────────────────────────────────────
// Actions
// ──────────────────────────────────────────────

- (void)registerDummyApp {
    NSString *output = [self runHelperCommand:@"/usr/libexec/snddebug" arg:@"com.apple.Preferences"];
    if (output.length > 0 && ![output hasPrefix:@"Error"]) {
        [self loadStats];
        [self.tableView reloadData];
        [self showAlert:@"Success" message:@"Token generated and copied."];
    } else {
        [self showAlert:@"Error" message:output ?: @"Unknown error"];
    }
}

- (void)testDaemonConnection {
    NSString *output = [self runHelperCommand:@"/usr/libexec/snddebug" arg:@"com.apple.Preferences"];
    if ([output rangeOfString:@"Daemon unreachable"].location != NSNotFound) {
        [self showAlert:@"Dead" message:@"Daemon unreachable."];
    } else {
        [self showAlert:@"Alive" message:@"Daemon is listening."];
    }
}

- (NSString *)runHelperCommand:(NSString *)cmd arg:(NSString *)arg {
    int out_pipe[2];
    pipe(out_pipe);
    posix_spawn_file_actions_t action;
    posix_spawn_file_actions_init(&action);
    posix_spawn_file_actions_adddup2(&action, out_pipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&action, out_pipe[0]);
    pid_t pid;
    const char *argv[] = { [cmd UTF8String], [arg UTF8String], NULL };
    extern char **environ;
    posix_spawn(&pid, [cmd UTF8String], &action, NULL, (char *const *)argv, environ);
    close(out_pipe[1]);
    posix_spawn_file_actions_destroy(&action);
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    ssize_t bytesRead = read(out_pipe[0], buffer, sizeof(buffer) - 1);
    close(out_pipe[0]);
    waitpid(pid, NULL, 0);
    return bytesRead > 0 ? [NSString stringWithUTF8String:buffer] : @"";
}

- (void)showAlert:(NSString *)title message:(NSString *)msg {
    UIAlertView *av = [[UIAlertView alloc] initWithTitle:title
                                                 message:msg
                                                delegate:nil
                                       cancelButtonTitle:@"OK"
                                       otherButtonTitles:nil];
    [av show];
}

@end