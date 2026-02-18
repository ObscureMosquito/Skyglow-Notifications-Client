#import "SNServerInfoViewController.h"
#import "SNDataManager.h"
#include <spawn.h>
#include <sys/wait.h>

extern NSString *RegisterAccount(NSString *serverAddress);
extern char **environ;

typedef enum {
    SectionStatus = 0,
    SectionServer,
    SectionCertificate,
    SectionDevice,
    SectionActions,
    SectionCount
} ServerInfoSection;

@interface SNServerInfoViewController () {
    NSString *_serverAddress;
    NSString *_resolvedIP;
    NSString *_resolvedPort;
    NSString *_deviceAddress;
    NSString *_connectionStatus;
    NSString *_lastUpdated;
    NSString *_certSubject;
    NSString *_certIssuer;
    NSString *_certExpiry;
    BOOL      _isRegistered;
    BOOL      _isEnabled;
}
@end

@implementation SNServerInfoViewController

- (void)setRootController:(id)controller {}
- (void)setParentController:(id)controller {}
- (void)setSpecifier:(id)specifier {}

- (id)init {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        self.title = @"Registration Info";
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    [self loadData];
    
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                    (__bridge const void *)(self),
                                    SNServerInfoStatusChanged,
                                    CFSTR("com.skyglow.snd.request_update"),
                                    NULL,
                                    CFNotificationSuspensionBehaviorDeliverImmediately);
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self loadData];
    [self.tableView reloadData];
}

- (void)dealloc {
    CFNotificationCenterRemoveObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                       (__bridge const void *)(self),
                                       CFSTR("com.skyglow.snd.request_update"),
                                       NULL);
}

static void SNServerInfoStatusChanged(CFNotificationCenterRef center,
                                      void *observer,
                                      CFStringRef name,
                                      const void *object,
                                      CFDictionaryRef userInfo) {
    SNServerInfoViewController *vc = (__bridge SNServerInfoViewController *)observer;
    dispatch_async(dispatch_get_main_queue(), ^{
        [vc loadData];
        [vc.tableView reloadData];
    });
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Data loading  (all via SNDataManager)
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

- (void)loadData {
    SNDataManager *dm = [SNDataManager shared];
    
    _isEnabled        = [dm isEnabled];
    _serverAddress    = [dm serverAddress];
    _deviceAddress    = [dm deviceAddress];
    _isRegistered     = [dm isRegistered];
    _connectionStatus = [dm connectionStatus];
    
    NSDate *updated = [dm lastUpdated];
    if (updated) {
        NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
        [fmt setDateStyle:NSDateFormatterShortStyle];
        [fmt setTimeStyle:NSDateFormatterMediumStyle];
        _lastUpdated = [fmt stringFromDate:updated];
    } else {
        _lastUpdated = @"â€”";
    }
    
    NSDictionary *certInfo = [dm parseCertificatePEM:[dm serverPubKeyPEM]];
    _certSubject = [certInfo objectForKey:@"subject"];
    _certIssuer  = [certInfo objectForKey:@"issuer"];
    _certExpiry  = [certInfo objectForKey:@"expiry"];
    
    NSDictionary *dns = [dm cachedDNSForServerAddress:_serverAddress];
    _resolvedIP   = [dns objectForKey:@"ip"];
    _resolvedPort = [dns objectForKey:@"port"];
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// TableView DataSource
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return _isRegistered ? SectionCount : 2;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (!_isRegistered) {
        if (section == 0) return 1;
        if (section == 1) return 1;
        return 0;
    }
    switch ((ServerInfoSection)section) {
        case SectionStatus:      return 3;
        case SectionServer:      return 2;
        case SectionCertificate: return 3;
        case SectionDevice:      return 1;
        case SectionActions:     return 1;
        default: return 0;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (!_isRegistered) return (section == 0) ? @"Status" : nil;
    switch ((ServerInfoSection)section) {
        case SectionStatus:      return @"Connection";
        case SectionServer:      return @"Server";
        case SectionCertificate: return @"Certificate";
        case SectionDevice:      return @"Device";
        case SectionActions:     return nil;
        default: return nil;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (!_isRegistered && section == 0)
        return @"No server configured. Enter a server address above, then tap Register.";
    if (_isRegistered && section == SectionActions)
        return @"Unregistering removes your profile and stops all Skyglow notifications.";
    return nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *valueCellID  = @"ValueCell";
    static NSString *actionCellID = @"ActionCell";
    
    SNDataManager *dm = [SNDataManager shared];
    
    // â”€â”€ Not registered â”€â”€
    if (!_isRegistered) {
        if (indexPath.section == 0) {
            UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:valueCellID];
            if (!cell)
                cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1
                                               reuseIdentifier:valueCellID];
            cell.textLabel.text = @"Registration";
            cell.detailTextLabel.text = @"Not Registered";
            cell.detailTextLabel.textColor = [UIColor grayColor];
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
            return cell;
        }
        UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:actionCellID];
        if (!cell)
            cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                           reuseIdentifier:actionCellID];
        cell.textLabel.text = @"Register";
        cell.textLabel.textAlignment = NSTextAlignmentCenter;
        cell.textLabel.textColor = [UIColor colorWithRed:0.0 green:0.478 blue:1.0 alpha:1.0];
        return cell;
    }
    
    // â”€â”€ Actions â”€â”€
    ServerInfoSection section = (ServerInfoSection)indexPath.section;
    
    if (section == SectionActions) {
        UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:actionCellID];
        if (!cell)
            cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                           reuseIdentifier:actionCellID];
        cell.textLabel.text = @"Unregister";
        cell.textLabel.textAlignment = NSTextAlignmentCenter;
        cell.textLabel.textColor = [UIColor colorWithRed:0.85 green:0.2 blue:0.2 alpha:1.0];
        return cell;
    }
    
    // â”€â”€ Value rows â”€â”€
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:valueCellID];
    if (!cell)
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1
                                       reuseIdentifier:valueCellID];
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    cell.accessoryType  = UITableViewCellAccessoryNone;
    cell.detailTextLabel.textColor = [UIColor darkGrayColor];
    
    switch (section) {
        case SectionStatus:
            switch (indexPath.row) {
                case 0:
                    cell.textLabel.text = @"Status";
                    cell.detailTextLabel.text = [dm friendlyStatusString:_connectionStatus];
                    cell.detailTextLabel.textColor = [dm colorForStatus:_connectionStatus];
                    break;
                case 1:
                    cell.textLabel.text = @"Last Updated";
                    cell.detailTextLabel.text = _lastUpdated;
                    break;
                case 2:
                    cell.textLabel.text = @"Enabled";
                    cell.detailTextLabel.text = _isEnabled ? @"Yes" : @"No";
                    break;
            }
            break;
        case SectionServer:
            switch (indexPath.row) {
                case 0:
                    cell.textLabel.text = @"Address";
                    cell.detailTextLabel.text = _serverAddress ?: @"â€”";
                    break;
                case 1:
                    cell.textLabel.text = @"Endpoint";
                    cell.detailTextLabel.text = (_resolvedIP && _resolvedPort)
                    ? [NSString stringWithFormat:@"%@:%@", _resolvedIP, _resolvedPort]
                    : @"Not resolved";
                    break;
            }
            break;
        case SectionCertificate:
            switch (indexPath.row) {
                case 0: cell.textLabel.text = @"Common Name"; cell.detailTextLabel.text = _certSubject ?: @"â€”"; break;
                case 1: cell.textLabel.text = @"Issuer";      cell.detailTextLabel.text = _certIssuer  ?: @"â€”"; break;
                case 2: cell.textLabel.text = @"Expires";     cell.detailTextLabel.text = _certExpiry  ?: @"â€”"; break;
            }
            break;
        case SectionDevice:
            cell.textLabel.text = @"Device Address";
            cell.detailTextLabel.text = _deviceAddress ?: @"â€”";
            cell.selectionStyle = UITableViewCellSelectionStyleBlue;
            break;
        default: break;
    }
    return cell;
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// TableView Delegate
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    
    if (!_isRegistered) {
        if (indexPath.section == 1) [self performRegistration];
        return;
    }
    
    ServerInfoSection section = (ServerInfoSection)indexPath.section;
    
    if (section == SectionActions) {
        [self confirmUnregister];
    } else if (section == SectionDevice && _deviceAddress) {
        [[UIPasteboard generalPasteboard] setString:_deviceAddress];
        [[[UIAlertView alloc] initWithTitle:@"Copied"
                                    message:@"Device address copied."
                                   delegate:nil
                          cancelButtonTitle:@"OK"
                          otherButtonTitles:nil] show];
    }
}

// Daemon restart helper

- (void)reloadDaemon {
    NSString *path = [[NSBundle bundleForClass:[self class]]
                      pathForResource:@"sndrestart" ofType:nil];
    if (!path) {
        NSLog(@"[ServerInfo] sndrestart not found in bundle");
        return;
    }
    pid_t pid = 0;
    const char *cpath = [path fileSystemRepresentation];
    char *const args[] = { (char *)cpath, NULL };
    if (posix_spawn(&pid, cpath, NULL, NULL, args, environ) == 0) {
        waitpid(pid, NULL, 0);
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Registration
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

- (void)performRegistration {
    NSString *inputAddress = [[SNDataManager shared] serverAddressInput];
    if (!inputAddress || inputAddress.length == 0) {
        [[[UIAlertView alloc] initWithTitle:@"Error"
                                    message:@"Please enter a server address first."
                                   delegate:nil
                          cancelButtonTitle:@"OK"
                          otherButtonTitles:nil] show];
        return;
    }
    
    UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"Registering"
                                                    message:@"\n"
                                                   delegate:nil
                                          cancelButtonTitle:nil
                                          otherButtonTitles:nil];
    UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc]
                                        initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhiteLarge];
    [alert show];
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
                       spinner.center = CGPointMake(CGRectGetMidX(alert.bounds), CGRectGetMidY(alert.bounds) + 20);
                       [alert addSubview:spinner];
                       [spinner startAnimating];
                   });
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Clean stale data before re-registering (new identity = old tokens useless)
        [[SNDataManager shared] clearAllTokens];
        [[SNDataManager shared] clearDNSCache];
        
        NSString *result = RegisterAccount(inputAddress);
        
        if (!result) {
            // Registration succeeded â restart the daemon so it picks up the
            // new profile. Posting reload_config alone isn't enough because
            // the daemon may have exited (return 0) when it had no profile.
            [self reloadDaemon];
        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [alert dismissWithClickedButtonIndex:0 animated:YES];
            if (result) {
                [[[UIAlertView alloc] initWithTitle:@"Registration Failed"
                                            message:[NSString stringWithFormat:@"Error: %@", result]
                                           delegate:nil
                                  cancelButtonTitle:@"OK"
                                  otherButtonTitles:nil] show];
            } else {
                [self loadData];
                [self.tableView reloadData];
                // Post UI refresh so other views update
                CFNotificationCenterPostNotificationWithOptions(
                    CFNotificationCenterGetDarwinNotifyCenter(),
                    CFSTR("com.skyglow.snd.request_update"),
                    NULL, NULL, kCFNotificationDeliverImmediately);
            }
        });
    });
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Unregistration
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

- (void)confirmUnregister {
    [[[UIAlertView alloc]
      initWithTitle:@"Unregister?"
      message:@"This will remove your server profile and stop all notifications."
      delegate:self
      cancelButtonTitle:@"Cancel"
      otherButtonTitles:@"Unregister", nil] show];
}

- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex {
    if (buttonIndex == 1) {
        [[SNDataManager shared] unregister];
        [self loadData];
        [self.tableView reloadData];
    }
}

@end