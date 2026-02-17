#import "SNServerInfoViewController.h"
#import <sqlite3.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>

// 1. Declare the registration function (or import header if available)
// #include "skyglownotificationsdaemonsettings/SNRegisterAccount.h"
extern NSString *RegisterAccount(NSString *serverAddress);

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

- (void)setRootController:(id)controller {
    // Required stub.
}

- (void)setParentController:(id)controller {
    // Required stub.
}

- (void)setSpecifier:(id)specifier {
    // Required stub.
}

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

// ──────────────────────────────────────────────
// Data loading
// ──────────────────────────────────────────────

- (void)loadData {
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:
                           @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist"];
    _isEnabled = [[prefs objectForKey:@"enabled"] boolValue];

    NSDictionary *profile = [NSDictionary dictionaryWithContentsOfFile:
                             @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist"];
    _serverAddress = [profile objectForKey:@"server_address"];
    _deviceAddress = [profile objectForKey:@"device_address"];
    _isRegistered  = (_serverAddress != nil && [_serverAddress length] > 0);

    NSString *certPEM = [profile objectForKey:@"server_pub_key"];
    [self parseCertificate:certPEM];

    NSDictionary *status = [NSDictionary dictionaryWithContentsOfFile:
                            @"/var/mobile/Library/Preferences/com.skyglow.sndp.status.plist"];
    _connectionStatus = [status objectForKey:@"currentStatus"];
    NSDate *updated    = [status objectForKey:@"lastUpdated"];
    if (updated) {
        NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
        [fmt setDateStyle:NSDateFormatterShortStyle];
        [fmt setTimeStyle:NSDateFormatterMediumStyle];
        _lastUpdated = [fmt stringFromDate:updated];
    } else {
        _lastUpdated = @"—";
    }

    _resolvedIP   = nil;
    _resolvedPort = nil;
    [self loadCachedDNS];
}

- (void)loadCachedDNS {
    if (!_serverAddress) return;

    NSString *dbPath = @"/var/mobile/Library/SkyglowNotifications/sqlite.db";
    if (![[NSFileManager defaultManager] fileExistsAtPath:dbPath]) return;

    sqlite3 *db = NULL;
    if (sqlite3_open_v2([dbPath UTF8String], &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return;

    NSString *dnsKey = [NSString stringWithFormat:@"_sgn.%@", _serverAddress];
    const char *sql  = "SELECT ip, port FROM dns_cache WHERE domain = ?";
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, [dnsKey UTF8String], -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *ip   = (const char *)sqlite3_column_text(stmt, 0);
            const char *port = (const char *)sqlite3_column_text(stmt, 1);
            if (ip)   _resolvedIP   = [NSString stringWithUTF8String:ip];
            if (port) _resolvedPort = [NSString stringWithUTF8String:port];
        }
    }
    if (stmt) sqlite3_finalize(stmt);
    sqlite3_close(db);
}

- (void)parseCertificate:(NSString *)certPEM {
    _certSubject = nil;
    _certIssuer  = nil;
    _certExpiry  = nil;

    if (!certPEM || [certPEM length] == 0) return;

    const char *pemData = [certPEM UTF8String];
    BIO *bio = BIO_new_mem_buf((void *)pemData, -1);
    if (!bio) return;

    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cert) return;

    char buf[512];
    X509_NAME *subjectName = X509_get_subject_name(cert);
    if (subjectName) {
        int cnIdx = X509_NAME_get_index_by_NID(subjectName, NID_commonName, -1);
        if (cnIdx >= 0) {
            X509_NAME_ENTRY *entry = X509_NAME_get_entry(subjectName, cnIdx);
            ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
            if (data) {
                unsigned char *utf8 = NULL;
                int len = ASN1_STRING_to_UTF8(&utf8, data);
                if (len > 0 && utf8) {
                    _certSubject = [NSString stringWithUTF8String:(char *)utf8];
                    OPENSSL_free(utf8);
                }
            }
        }
        if (!_certSubject) {
            X509_NAME_oneline(subjectName, buf, sizeof(buf));
            _certSubject = [NSString stringWithUTF8String:buf];
        }
    }

    X509_NAME *issuerName = X509_get_issuer_name(cert);
    if (issuerName) {
        int orgIdx = X509_NAME_get_index_by_NID(issuerName, NID_organizationName, -1);
        if (orgIdx >= 0) {
            X509_NAME_ENTRY *entry = X509_NAME_get_entry(issuerName, orgIdx);
            ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
            if (data) {
                unsigned char *utf8 = NULL;
                int len = ASN1_STRING_to_UTF8(&utf8, data);
                if (len > 0 && utf8) {
                    _certIssuer = [NSString stringWithUTF8String:(char *)utf8];
                    OPENSSL_free(utf8);
                }
            }
        }
        if (!_certIssuer) {
            X509_NAME_oneline(issuerName, buf, sizeof(buf));
            _certIssuer = [NSString stringWithUTF8String:buf];
        }
    }

    ASN1_TIME *notAfter = X509_get_notAfter(cert);
    if (notAfter) {
        BIO *timeBio = BIO_new(BIO_s_mem());
        if (timeBio) {
            ASN1_TIME_print(timeBio, notAfter);
            char timeBuf[128];
            int readLen = BIO_read(timeBio, timeBuf, sizeof(timeBuf) - 1);
            if (readLen > 0) {
                timeBuf[readLen] = '\0';
                _certExpiry = [NSString stringWithUTF8String:timeBuf];
            }
            BIO_free(timeBio);
        }
    }
    X509_free(cert);
}

// ──────────────────────────────────────────────
// TableView DataSource
// ──────────────────────────────────────────────

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    if (!_isRegistered) return 2;
    return SectionCount;
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
    if (!_isRegistered) {
        if (section == 0) return @"Status";
        return nil;
    }
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
    if (!_isRegistered && section == 1) {
        return @"Enter your server address in the main menu before registering.";
    }
    if (_isRegistered && section == SectionActions) {
        return @"Unregistering will remove your server profile and disable notifications.";
    }
    return nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *valueCellID   = @"ValueCell";
    static NSString *actionCellID  = @"ActionCell";

    if (!_isRegistered) {
        if (indexPath.section == 1) {
            UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:actionCellID];
            if (!cell) {
                cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                              reuseIdentifier:actionCellID];
            }
            cell.textLabel.text = @"Register Device";
            cell.textLabel.textAlignment = NSTextAlignmentCenter;
            cell.textLabel.textColor = [UIColor colorWithRed:0.2 green:0.75 blue:0.2 alpha:1.0];
            
            cell.selectionStyle = UITableViewCellSelectionStyleBlue;
            return cell;
        } else {
            UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:valueCellID];
            if (!cell) {
                cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1
                                              reuseIdentifier:valueCellID];
            }
            cell.textLabel.text = @"Registration";
            cell.detailTextLabel.text = @"Not Registered";
            cell.detailTextLabel.textColor = [UIColor grayColor];
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
            return cell;
        }
    }

    // ── Registered View ──
    ServerInfoSection section = (ServerInfoSection)indexPath.section;

    if (section == SectionActions) {
        UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:actionCellID];
        if (!cell) {
            cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                          reuseIdentifier:actionCellID];
        }
        cell.textLabel.text = @"Unregister";
        cell.textLabel.textAlignment = NSTextAlignmentCenter;
        cell.textLabel.textColor = [UIColor colorWithRed:0.85 green:0.2 blue:0.2 alpha:1.0];
        cell.selectionStyle = UITableViewCellSelectionStyleBlue;
        return cell;
    }

    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:valueCellID];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1
                                      reuseIdentifier:valueCellID];
    }

    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    cell.accessoryType  = UITableViewCellAccessoryNone;
    cell.detailTextLabel.textColor = [UIColor darkGrayColor];

    switch (section) {
        case SectionStatus: {
            switch (indexPath.row) {
                case 0:
                    cell.textLabel.text = @"Status";
                    cell.detailTextLabel.text = [self friendlyStatus:_connectionStatus];
                    cell.detailTextLabel.textColor = [self colorForStatus:_connectionStatus];
                    break;
                case 1:
                    cell.textLabel.text = @"Last Updated";
                    cell.detailTextLabel.text = _lastUpdated ?: @"—";
                    break;
                case 2:
                    cell.textLabel.text = @"Enabled";
                    cell.detailTextLabel.text = _isEnabled ? @"Yes" : @"No";
                    break;
            }
            break;
        }
        case SectionServer: {
            switch (indexPath.row) {
                case 0:
                    cell.textLabel.text = @"Address";
                    cell.detailTextLabel.text = _serverAddress ?: @"—";
                    break;
                case 1:
                    cell.textLabel.text = @"Endpoint";
                    if (_resolvedIP && _resolvedPort) {
                        cell.detailTextLabel.text = [NSString stringWithFormat:@"%@:%@", _resolvedIP, _resolvedPort];
                    } else {
                        cell.detailTextLabel.text = @"Not resolved";
                    }
                    break;
            }
            break;
        }
        case SectionCertificate: {
            switch (indexPath.row) {
                case 0:
                    cell.textLabel.text = @"Common Name";
                    cell.detailTextLabel.text = _certSubject ?: @"—";
                    break;
                case 1:
                    cell.textLabel.text = @"Issuer";
                    cell.detailTextLabel.text = _certIssuer ?: @"—";
                    break;
                case 2:
                    cell.textLabel.text = @"Expires";
                    cell.detailTextLabel.text = _certExpiry ?: @"—";
                    break;
            }
            break;
        }
        case SectionDevice: {
            cell.textLabel.text = @"Device Address";
            cell.detailTextLabel.text = _deviceAddress ?: @"—";
            cell.selectionStyle = UITableViewCellSelectionStyleBlue;
            break;
        }
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
        if (indexPath.section == 1 && indexPath.row == 0) {
            [self performRegistration];
        }
        return;
    }

    ServerInfoSection section = (ServerInfoSection)indexPath.section;

    if (section == SectionActions && indexPath.row == 0) {
        [self confirmUnregister];
        return;
    }

    if (section == SectionDevice && indexPath.row == 0 && _deviceAddress) {
        [self copyToClipboard:_deviceAddress label:@"Device address"];
    }
}

// ──────────────────────────────────────────────
// Registration Logic
// ──────────────────────────────────────────────

- (void)performRegistration {
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:
                           @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist"];
    NSString *inputAddress = [prefs objectForKey:@"notificationServerAddress"];

    if (!inputAddress || inputAddress.length == 0) {
        [[[UIAlertView alloc] initWithTitle:@"Error"
                                    message:@"Please enter a server address in the Configuration menu."
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
    UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhiteLarge];
    [alert show];
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        CGRect b = alert.bounds;
        spinner.center = CGPointMake(CGRectGetMidX(b), CGRectGetMidY(b) + 20);
        [alert addSubview:spinner];
        [spinner startAnimating];
    });

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        
        NSString *result = RegisterAccount(inputAddress);

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
                
                CFNotificationCenterPostNotificationWithOptions(
                    CFNotificationCenterGetDarwinNotifyCenter(),
                    CFSTR("com.skyglow.snd.request_update"),
                    NULL, NULL, kCFNotificationDeliverImmediately);
            }
        });
    });
}

// ──────────────────────────────────────────────
// Unregistration Logic
// ──────────────────────────────────────────────

- (void)confirmUnregister {
    UIAlertView *alert = [[UIAlertView alloc]
        initWithTitle:@"Unregister?"
              message:@"This will remove your server profile. You will stop receiving notifications."
             delegate:self
    cancelButtonTitle:@"Cancel"
    otherButtonTitles:@"Unregister", nil];
    [alert show];
}

- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex {
    if (buttonIndex == 1) {
        [self performUnregister];
    }
}

- (void)performUnregister {
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:@"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist" error:nil];

    NSString *prefsPath = @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist";
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:prefsPath];
    if (!prefs) prefs = [NSMutableDictionary dictionary];
    [prefs setObject:@NO forKey:@"enabled"];
    [prefs writeToFile:prefsPath atomically:YES];

    NSDictionary *statusDict = @{
        @"lastUpdated": [NSDate date],
        @"currentStatus": @"Disabled"
    };
    [statusDict writeToFile:@"/var/mobile/Library/Preferences/com.skyglow.sndp.status.plist" atomically:YES];

    CFNotificationCenterPostNotificationWithOptions(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFSTR("com.skyglow.snd.request_update"),
        NULL, NULL, kCFNotificationDeliverImmediately);

    [self loadData];
    [self.tableView reloadData];
}

- (void)copyToClipboard:(NSString *)text label:(NSString *)label {
    UIPasteboard *pb = [UIPasteboard generalPasteboard];
    [pb setString:text];
    [[[UIAlertView alloc] initWithTitle:@"Copied"
                                message:[NSString stringWithFormat:@"%@ copied.", label]
                               delegate:nil
                      cancelButtonTitle:@"OK"
                      otherButtonTitles:nil] show];
}

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

- (NSString *)friendlyStatus:(NSString *)status {
    if ([status isEqualToString:@"Connected"]) return @"Connected";
    if ([status isEqualToString:@"ConnectedNotAuthenticated"]) return @"Authenticating…";
    if ([status isEqualToString:@"EnabledNotConnected"]) return @"Connecting…";
    if ([status isEqualToString:@"Disabled"]) return @"Disabled";
    if ([status isEqualToString:@"ServerConfigBad"]) return @"Bad Config";
    return status ?: @"Unknown";
}

- (UIColor *)colorForStatus:(NSString *)status {
    if ([status isEqualToString:@"Connected"]) return [UIColor colorWithRed:0.2 green:0.7 blue:0.2 alpha:1.0];
    if ([status isEqualToString:@"Disabled"]) return [UIColor grayColor];
    if ([status isEqualToString:@"EnabledNotConnected"]) return [UIColor orangeColor];
    if ([status isEqualToString:@"Error"]) return [UIColor redColor];
    return [UIColor darkGrayColor];
}

@end