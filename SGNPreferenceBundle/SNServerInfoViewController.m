#import "SNServerInfoViewController.h"
#import "SNDataManager.h"
#include <spawn.h>
#include <sys/wait.h>
#import <objc/runtime.h>
#import <objc/message.h>

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
    // ── Profile / config ─────────────────────────────────────────
    NSString *_serverAddress;
    NSString *_resolvedIP;
    NSString *_resolvedPort;
    NSString *_deviceAddress;
    NSString *_certSubject;
    NSString *_certIssuer;
    NSString *_certExpiry;
    BOOL      _isRegistered;
    BOOL      _isEnabled;

    // ── Live daemon status (from StatusServer socket) ─────────────
    // Stored as the raw payload so we never lose information.
    // All display strings are derived from this on demand.
    SGStatusPayload _statusPayload;
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
        memset(&_statusPayload, 0, sizeof(_statusPayload));
        _statusPayload.state = SGStateStarting;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    [self loadData];

    // "com.skyglow.snd.request_update" is the UI-to-UI refresh signal.
    // It is NOT the daemon reload signal (reload_config).
    // We listen here so that unregister/register in other view controllers
    // triggers a refresh of this screen too.
    CFNotificationCenterAddObserver(
        CFNotificationCenterGetDarwinNotifyCenter(),
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
    CFNotificationCenterRemoveObserver(
        CFNotificationCenterGetDarwinNotifyCenter(),
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

// ──────────────────────────────────────────────
// Data loading
// ──────────────────────────────────────────────

- (void)loadData {
    SNDataManager *dm = [SNDataManager shared];

    // ── Config / profile ─────────────────────────────────────────
    _isEnabled     = [dm isEnabled];
    _serverAddress = [dm serverAddress];
    _deviceAddress = [dm deviceAddress];
    _isRegistered  = [dm isRegistered];

    NSDictionary *certInfo = [dm parseCertificatePEM:[dm serverPubKeyPEM]];
    _certSubject = certInfo[@"subject"];
    _certIssuer  = certInfo[@"issuer"];
    _certExpiry  = certInfo[@"expiry"];

    NSDictionary *dns = [dm cachedDNSForServerAddress:_serverAddress];
    _resolvedIP   = dns[@"ip"];
    _resolvedPort = dns[@"port"];

    // ── Live daemon status (socket query) ─────────────────────────
    // Called synchronously; queryDaemonStatus has a 300 ms timeout
    // and returns a safe empty payload if the daemon is unreachable.
    _statusPayload = [dm queryDaemonStatus];
}

// ── Formatting helpers ────────────────────────────────────────────

/// Human-readable timestamp from an epoch value (0 → "—").
- (NSString *)formattedTimestamp:(int64_t)epoch {
    if (epoch == 0) return @"—";
    NSDate *date = [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)epoch];
    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    [fmt setDateStyle:NSDateFormatterShortStyle];
    [fmt setTimeStyle:NSDateFormatterMediumStyle];
    return [fmt stringFromDate:date];
}

/// "Xh Ym" uptime string derived from daemon start time. Returns @"—" if
/// startTime is 0 (daemon not running or not heard from yet).
- (NSString *)formattedUptime {
    if (_statusPayload.startTime == 0) return @"—";
    int64_t now     = (int64_t)time(NULL);
    int64_t elapsed = now - _statusPayload.startTime;
    if (elapsed < 0)  return @"—";
    if (elapsed < 60) return [NSString stringWithFormat:@"%llds", (long long)elapsed];
    long long mins  = elapsed / 60;
    long long hours = mins / 60;
    mins %= 60;
    if (hours > 0) return [NSString stringWithFormat:@"%lldh %lldm", hours, mins];
    return [NSString stringWithFormat:@"%lldm", mins];
}

// ──────────────────────────────────────────────
// TableView DataSource
// ──────────────────────────────────────────────

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return _isRegistered ? SectionCount : 2;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (!_isRegistered) {
        return (section == 0 || section == 1) ? 1 : 0;
    }
    switch ((ServerInfoSection)section) {
        case SectionStatus:      return 5; // Status, Updated, Uptime, Failures, Enabled
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

    // ── Not registered ───────────────────────────────────────────
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

    // ── Actions ───────────────────────────────────────────────────
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

    // ── Value rows ────────────────────────────────────────────────
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:valueCellID];
    if (!cell)
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1
                                       reuseIdentifier:valueCellID];
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    cell.accessoryType  = UITableViewCellAccessoryNone;
    cell.detailTextLabel.textColor = [UIColor darkGrayColor];

    SGState state = (SGState)_statusPayload.state;

    switch (section) {
        case SectionStatus:
            switch (indexPath.row) {
                case 0:
                    cell.textLabel.text = @"Status";
                    cell.detailTextLabel.text  = [dm friendlyStringForState:state];
                    cell.detailTextLabel.textColor = [dm colorForState:state];
                    break;
                case 1:
                    cell.textLabel.text = @"Last Updated";
                    cell.detailTextLabel.text = [self formattedTimestamp:_statusPayload.timestamp];
                    break;
                case 2:
                    cell.textLabel.text = @"Uptime";
                    cell.detailTextLabel.text = [self formattedUptime];
                    break;
                case 3: {
                    cell.textLabel.text = @"Failures";
                    uint32_t f = _statusPayload.consecutiveFailures;
                    cell.detailTextLabel.text = f > 0
                        ? [NSString stringWithFormat:@"%u", f]
                        : @"0";
                    cell.detailTextLabel.textColor = f > 0
                        ? [UIColor colorWithRed:0.85 green:0.2 blue:0.2 alpha:1.0]
                        : [UIColor darkGrayColor];
                    break;
                }
                case 4:
                    cell.textLabel.text = @"Enabled";
                    cell.detailTextLabel.text = _isEnabled ? @"Yes" : @"No";
                    break;
            }
            break;

        case SectionServer:
            switch (indexPath.row) {
                case 0:
                    cell.textLabel.text = @"Address";
                    cell.detailTextLabel.text = _serverAddress ?: @"—";
                    break;
                case 1: {
                    // Prefer live IP from status payload (what the daemon
                    // actually connected to), fall back to cached DNS.
                    NSString *liveIP = nil;
                    if (_statusPayload.serverIP[0] != '\0') {
                        liveIP = [NSString stringWithUTF8String:_statusPayload.serverIP];
                    }
                    NSString *ip   = liveIP ?: _resolvedIP;
                    NSString *port = _resolvedPort;
                    cell.textLabel.text = @"Endpoint";
                    cell.detailTextLabel.text = (ip && port)
                        ? [NSString stringWithFormat:@"%@:%@", ip, port]
                        : (ip ?: @"Not resolved");
                    break;
                }
            }
            break;

        case SectionCertificate:
            switch (indexPath.row) {
                case 0: cell.textLabel.text = @"Common Name"; cell.detailTextLabel.text = _certSubject ?: @"—"; break;
                case 1: cell.textLabel.text = @"Issuer";      cell.detailTextLabel.text = _certIssuer  ?: @"—"; break;
                case 2: cell.textLabel.text = @"Expires";     cell.detailTextLabel.text = _certExpiry  ?: @"—"; break;
            }
            break;

        case SectionDevice:
            cell.textLabel.text = @"Device Address";
            cell.detailTextLabel.text = _deviceAddress ?: @"—";
            cell.selectionStyle = UITableViewCellSelectionStyleBlue;
            break;

        default: break;
    }
    return cell;
}

// ──────────────────────────────────────────────
// TableView Delegate
// ──────────────────────────────────────────────

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
        [self showMessage:@"Device address copied." withTitle:@"Copied"];
    }
}

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

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

- (void)showMessage:(NSString *)message withTitle:(NSString *)title {
    Class alertControllerClass = NSClassFromString(@"UIAlertController");

    if (alertControllerClass) {
        SEL alertCreateSel = NSSelectorFromString(@"alertControllerWithTitle:message:preferredStyle:");
        id (*createAlert)(Class, SEL, id, id, NSInteger) = (id (*)(Class, SEL, id, id, NSInteger))objc_msgSend;
        id alert = createAlert(alertControllerClass, alertCreateSel, title, message, 1);

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
        [[[UIAlertView alloc] initWithTitle:title
                                    message:message
                                   delegate:nil
                          cancelButtonTitle:@"OK"
                          otherButtonTitles:nil] show];
    }
}

// ──────────────────────────────────────────────
// Registration
// ──────────────────────────────────────────────

- (void)performRegistration {
    NSString *inputAddress = [[SNDataManager shared] serverAddressInput];
    if (!inputAddress || inputAddress.length == 0) {
        [self showMessage:@"Please enter a server address first." withTitle:@"Error"];
        return;
    }

    __block id activeAlert = nil;
    UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc]
                                        initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhiteLarge];

    Class alertControllerClass = NSClassFromString(@"UIAlertController");
    if (alertControllerClass) {
        SEL alertCreateSel = NSSelectorFromString(@"alertControllerWithTitle:message:preferredStyle:");
        id (*createAlert)(Class, SEL, id, id, NSInteger) = (id (*)(Class, SEL, id, id, NSInteger))objc_msgSend;
        activeAlert = createAlert(alertControllerClass, alertCreateSel, @"Registering", @"\n\n\n", 1);

        SEL presentSel = NSSelectorFromString(@"presentViewController:animated:completion:");
        void (*present)(id, SEL, id, BOOL, id) = (void (*)(id, SEL, id, BOOL, id))objc_msgSend;
        present(self, presentSel, activeAlert, YES, nil);

        SEL viewSel = NSSelectorFromString(@"view");
        UIView *(*getView)(id, SEL) = (UIView *(*)(id, SEL))objc_msgSend;
        UIView *alertView = getView(activeAlert, viewSel);

        spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
        spinner.center = CGPointMake(CGRectGetMidX(alertView.bounds), CGRectGetMidY(alertView.bounds));
        [alertView addSubview:spinner];
        [spinner startAnimating];
    } else {
        UIAlertView *alertView = [[UIAlertView alloc] initWithTitle:@"Registering"
                                                            message:@"\n"
                                                           delegate:nil
                                                  cancelButtonTitle:nil
                                                  otherButtonTitles:nil];
        activeAlert = alertView;
        [alertView show];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
                           spinner.center = CGPointMake(CGRectGetMidX(alertView.bounds),
                                                        CGRectGetMidY(alertView.bounds) + 20);
                           [alertView addSubview:spinner];
                           [spinner startAnimating];
                       });
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [[SNDataManager shared] clearAllTokens];
        [[SNDataManager shared] clearDNSCache];

        NSString *result = RegisterAccount(inputAddress);

        if (!result) {
            // Restart daemon so it picks up the new profile
            [self reloadDaemon];
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            if (alertControllerClass) {
                SEL dismissSel = NSSelectorFromString(@"dismissViewControllerAnimated:completion:");
                void (*dismiss)(id, SEL, BOOL, id) = (void (*)(id, SEL, BOOL, id))objc_msgSend;
                dismiss(activeAlert, dismissSel, YES, nil);
            } else {
                [(UIAlertView *)activeAlert dismissWithClickedButtonIndex:0 animated:YES];
            }

            if (result) {
                [self showMessage:[NSString stringWithFormat:@"Error: %@", result]
                        withTitle:@"Registration Failed"];
            } else {
                [self loadData];
                [self.tableView reloadData];
                CFNotificationCenterPostNotificationWithOptions(
                    CFNotificationCenterGetDarwinNotifyCenter(),
                    CFSTR("com.skyglow.snd.request_update"),
                    NULL, NULL, kCFNotificationDeliverImmediately);
            }
        });
    });
}

// ──────────────────────────────────────────────
// Unregistration
// ──────────────────────────────────────────────

- (void)confirmUnregister {
    Class alertControllerClass = NSClassFromString(@"UIAlertController");

    if (alertControllerClass) {
        SEL alertCreateSel = NSSelectorFromString(@"alertControllerWithTitle:message:preferredStyle:");
        id (*createAlert)(Class, SEL, id, id, NSInteger) = (id (*)(Class, SEL, id, id, NSInteger))objc_msgSend;
        id alert = createAlert(alertControllerClass, alertCreateSel,
                               @"Unregister?",
                               @"This will remove your server profile and stop all notifications.", 1);

        Class alertActionClass = NSClassFromString(@"UIAlertAction");
        SEL actionCreateSel = NSSelectorFromString(@"actionWithTitle:style:handler:");

        id (*createCancel)(Class, SEL, id, NSInteger, id) = (id (*)(Class, SEL, id, NSInteger, id))objc_msgSend;
        id cancelAction = createCancel(alertActionClass, actionCreateSel, @"Cancel", 1, nil);

        __weak typeof(self) weakSelf = self;
        void (^unregisterBlock)(id) = ^(id action) {
            [[SNDataManager shared] unregister];
            [weakSelf loadData];
            [weakSelf.tableView reloadData];
        };
        id (*createDestructive)(Class, SEL, id, NSInteger, id) = (id (*)(Class, SEL, id, NSInteger, id))objc_msgSend;
        id unregisterAction = createDestructive(alertActionClass, actionCreateSel, @"Unregister", 2, unregisterBlock);

        SEL addActionSel = NSSelectorFromString(@"addAction:");
        void (*addAction)(id, SEL, id) = (void (*)(id, SEL, id))objc_msgSend;
        addAction(alert, addActionSel, cancelAction);
        addAction(alert, addActionSel, unregisterAction);

        SEL presentSel = NSSelectorFromString(@"presentViewController:animated:completion:");
        void (*present)(id, SEL, id, BOOL, id) = (void (*)(id, SEL, id, BOOL, id))objc_msgSend;
        present(self, presentSel, alert, YES, nil);
    } else {
        [[[UIAlertView alloc]
          initWithTitle:@"Unregister?"
          message:@"This will remove your server profile and stop all notifications."
          delegate:self
          cancelButtonTitle:@"Cancel"
          otherButtonTitles:@"Unregister", nil] show];
    }
}

- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex {
    if (buttonIndex == 1) {
        [[SNDataManager shared] unregister];
        [self loadData];
        [self.tableView reloadData];
    }
}

@end