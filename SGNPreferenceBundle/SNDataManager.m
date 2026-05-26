#import "SNDataManager.h"
#import "SNChannelGateway.h"
#import "../Skyglow-Notifications-Daemon/SGSharedConstants.h"
#import <UIKit/UIKit.h>
#import <sqlite3.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <unistd.h>
#include <dns_sd.h>

static const NSTimeInterval kSNAutoFetchDNSTimeoutSec  = 5.0;
static const NSTimeInterval kSNAutoFetchHTTPTimeoutSec = 10.0;
static NSString * const     kSNAutoFetchCertPath       = @"/snd/server_cert.pem";

static inline NSString * SGPath(NSString *path) {
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"]) {
        return [@"/var/jb" stringByAppendingString:path];
    }
    return path;
}

static inline NSString * SGMainPrefsPath() { return SGPath(SG_PREFS_PLIST_PATH); }
static inline NSString * SGProfilePathForIndex(NSInteger idx) {
    return SGPath([NSString stringWithFormat:SG_PROFILE_PLIST_FORMAT, (long)idx]);
}
static inline NSString * SGProfilePath() {
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:SGMainPrefsPath()];
    NSNumber *num = [prefs objectForKey:@"activeProfile"];
    NSInteger idx = (num && [num integerValue] >= 1 && [num integerValue] <= 5) ? [num integerValue] : 1;
    return SGProfilePathForIndex(idx);
}
static inline NSString * SGDBPath()        { return SGPath(SG_DB_PATH); }

@interface SNDataManager ()
@end

@interface SNAutoFetchConnectionDelegate : NSObject
@property (nonatomic, strong) NSMutableData *buffer;
@property (nonatomic, assign) NSInteger      statusCode;
@property (nonatomic, strong) NSError       *error;
@property (nonatomic, assign) BOOL           done;
@end
@implementation SNAutoFetchConnectionDelegate
- (id)init {
    if ((self = [super init])) { _buffer = [[NSMutableData alloc] init]; }
    return self;
}
- (void)dealloc {
    [_buffer release];
    [_error release];
    [super dealloc];
}
- (void)connection:(NSURLConnection *)c didFailWithError:(NSError *)e { _error = [e retain]; _done = YES; }
- (BOOL)connection:(NSURLConnection *)c canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)space {
    return [[space authenticationMethod] isEqualToString:NSURLAuthenticationMethodServerTrust];
}
- (void)connection:(NSURLConnection *)c didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)ch {
    if ([[[ch protectionSpace] authenticationMethod] isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        NSURLCredential *cred = [NSURLCredential credentialForTrust:[[ch protectionSpace] serverTrust]];
        [[ch sender] useCredential:cred forAuthenticationChallenge:ch];
    } else {
        [[ch sender] continueWithoutCredentialForAuthenticationChallenge:ch];
    }
}
- (void)connection:(NSURLConnection *)c didReceiveResponse:(NSURLResponse *)r {
    [_buffer setLength:0];
    _statusCode = [r isKindOfClass:[NSHTTPURLResponse class]] ? [(NSHTTPURLResponse *)r statusCode] : 0;
}
- (void)connection:(NSURLConnection *)c didReceiveData:(NSData *)data { [_buffer appendData:data]; }
- (void)connectionDidFinishLoading:(NSURLConnection *)c { _done = YES; }
@end

@implementation SNDataManager

+ (SNDataManager *)shared {
    static SNDataManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[SNDataManager alloc] init];
        [instance _bootstrapStatusMonitor];
    });
    return instance;
}

- (void)_bootstrapStatusMonitor {
    /* Cached payload starts zeroed (state == Starting, which renders as
     * neutral grey in the UI).  Two paths populate it:
     *
     *   1. One-shot QUERY_STATUS request — async; reply lands on main
     *      and fires SNDaemonStatusUpdated.  Covers bundle-load seeding
     *      and the rare case where state didn't change while suspended.
     *
     *   2. STATE_CHANGED subscription — pushes every future transition,
     *      survives suspend/resume and daemon restarts via Mach port
     *      lifecycle and the channel's reconnect machinery. */
    [SNChannelGateway queryStatusWithCompletion:^(SGStatusPayload payload) {
        self.latestPayload = payload;
        [[NSNotificationCenter defaultCenter] postNotificationName:@"SNDaemonStatusUpdated" object:nil];
    }];

    [SNChannelGateway subscribeToStatusUpdatesWithHandler:^(SGStatusPayload payload) {
        dispatch_async(dispatch_get_main_queue(), ^{
            self.latestPayload = payload;
            [[NSNotificationCenter defaultCenter] postNotificationName:@"SNDaemonStatusUpdated" object:nil];
        });
    }];
}

- (NSString *)mainPrefsPath { return SGMainPrefsPath(); }
- (NSString *)profilePath   { return SGProfilePath(); }
- (NSString *)dbPath        { return SGDBPath(); }

- (NSDictionary *)mainPrefs { return [NSDictionary dictionaryWithContentsOfFile:SGMainPrefsPath()] ?: @{}; }
- (BOOL)isEnabled { return [[[self mainPrefs] objectForKey:@"enabled"] boolValue]; }

- (NSDictionary *)appStatus { return [[self mainPrefs] objectForKey:@"appStatus"] ?: @{}; }

- (void)setAppStatusValue:(BOOL)value forBundleId:(NSString *)bundleId {
    if (!bundleId) return;
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:SGMainPrefsPath()] ?: [NSMutableDictionary dictionary];
    NSMutableDictionary *appSt = [NSMutableDictionary dictionaryWithDictionary:[prefs objectForKey:@"appStatus"] ?: @{}];
    [appSt setObject:@(value) forKey:bundleId];
    [prefs setObject:appSt forKey:@"appStatus"];
    [prefs writeToFile:SGMainPrefsPath() atomically:YES];
}

- (void)removeAppStatusForBundleId:(NSString *)bundleId {
    if (!bundleId) return;
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:SGMainPrefsPath()] ?: [NSMutableDictionary dictionary];

    NSMutableDictionary *appSt = [NSMutableDictionary dictionaryWithDictionary:[prefs objectForKey:@"appStatus"] ?: @{}];
    [appSt removeObjectForKey:bundleId];
    [prefs setObject:appSt forKey:@"appStatus"];

    [prefs writeToFile:SGMainPrefsPath() atomically:YES];
}

- (NSString *)serverAddressInput {
    return [[self mainPrefs] objectForKey:@"notificationServerAddress"];
}

- (void)clearDNSCache {
    sqlite3 *db = NULL;
    if (sqlite3_open([SGDBPath() UTF8String], &db) == SQLITE_OK) {
        sqlite3_exec(db, "DELETE FROM dns_cache;", NULL, NULL, NULL);
        sqlite3_close(db);
    }
}

- (void)clearAllTokens {
    sqlite3 *db = NULL;
    if (sqlite3_open([SGDBPath() UTF8String], &db) == SQLITE_OK) {
        sqlite3_exec(db, "DELETE FROM notifications;", NULL, NULL, NULL);
        sqlite3_close(db);
    }
}

- (void)setMainPrefValue:(id)value forKey:(NSString *)key {
    if (!key) return;
    NSMutableDictionary *prefs = [NSMutableDictionary dictionaryWithContentsOfFile:SGMainPrefsPath()] ?: [NSMutableDictionary dictionary];
    if (value) [prefs setObject:value forKey:key]; else [prefs removeObjectForKey:key];
    [prefs writeToFile:SGMainPrefsPath() atomically:YES];
}

- (NSDictionary *)profile { return [NSDictionary dictionaryWithContentsOfFile:SGProfilePath()] ?: @{}; }
- (NSString *)serverAddress   { return [[self profile] objectForKey:@"server_address"]; }
- (NSString *)deviceAddress   { return [[self profile] objectForKey:@"device_address"]; }
- (NSString *)serverPubKeyPEM { return [[self profile] objectForKey:@"server_pub_key"]; }
- (BOOL)isRegistered { return ([self serverAddress] != nil && [[self serverAddress] length] > 0); }

static sqlite3 *openDBReadOnly(void) {
    sqlite3 *db = NULL;
    if (![[NSFileManager defaultManager] fileExistsAtPath:SGDBPath()]) return NULL;
    if (sqlite3_open_v2([SGDBPath() UTF8String], &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return NULL;
    }
    return db;
}

- (NSArray *)allRegisteredTokens {
    sqlite3 *db = openDBReadOnly();
    if (!db) return @[];
    NSMutableArray *results = [NSMutableArray array];
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT bundle_id, token, routing_key FROM notifications ORDER BY bundle_id ASC", -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *bID = (const char *)sqlite3_column_text(stmt, 0);
            const void *tData = sqlite3_column_blob(stmt, 1);
            int tLen = sqlite3_column_bytes(stmt, 1);
            const void *rData = sqlite3_column_blob(stmt, 2);
            int rLen = sqlite3_column_bytes(stmt, 2);
            if (bID) {
                [results addObject:@{
                    @"bundleID": [NSString stringWithUTF8String:bID],
                    @"token": (tData && tLen > 0) ? [NSData dataWithBytes:tData length:tLen] : [NSData data],
                    @"routingKey": (rData && rLen > 0) ? [NSData dataWithBytes:rData length:rLen] : [NSData data],
                }];
            }
        }
    }
    if (stmt) sqlite3_finalize(stmt);
    sqlite3_close(db);
    return results;
}

- (NSSet *)registeredBundleIDs {
    sqlite3 *db = openDBReadOnly();
    if (!db) return [NSSet set];
    NSMutableSet *ids = [NSMutableSet set];
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT DISTINCT bundle_id FROM notifications", -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *bID = (const char *)sqlite3_column_text(stmt, 0);
            if (bID) [ids addObject:[NSString stringWithUTF8String:bID]];
        }
    }
    if (stmt) sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ids;
}

- (NSInteger)registeredTokenCount {
    sqlite3 *db = openDBReadOnly();
    if (!db) return 0;
    NSInteger count = 0;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT count(*) FROM notifications", -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) count = sqlite3_column_int(stmt, 0);
    }
    if (stmt) sqlite3_finalize(stmt);
    sqlite3_close(db);
    return count;
}

- (unsigned long long)dbFileSize {
    return [[[NSFileManager defaultManager] attributesOfItemAtPath:SGDBPath() error:nil] fileSize];
}

- (void)removeAppFromDatabase:(NSString *)bundleId {
    if (!bundleId) return;
    sqlite3 *db = NULL;
    if (sqlite3_open([SGDBPath() UTF8String], &db) == SQLITE_OK) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db, "DELETE FROM notifications WHERE bundle_id = ?", -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, [bundleId UTF8String], -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
        }
        if (stmt) sqlite3_finalize(stmt);
    }
    if (db) sqlite3_close(db);
}

- (NSDictionary *)cachedDNSForServerAddress:(NSString *)serverAddr {
    if (!serverAddr) return nil;
    sqlite3 *db = openDBReadOnly();
    if (!db) return nil;
    NSString *dnsKey = [NSString stringWithFormat:@"_sgn.%@", serverAddr];
    NSDictionary *result = nil;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT ip, port FROM dns_cache WHERE domain = ?", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, [dnsKey UTF8String], -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *ip = (const char *)sqlite3_column_text(stmt, 0);
            const char *port = (const char *)sqlite3_column_text(stmt, 1);
            if (ip && port) result = @{@"ip": [NSString stringWithUTF8String:ip], @"port": [NSString stringWithUTF8String:port]};
        }
    }
    if (stmt) sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

- (NSDictionary *)parseCertificatePEM:(NSString *)pem {
    if (!pem || [pem length] == 0) return nil;
    BIO *bio = BIO_new_mem_buf((void *)[pem UTF8String], -1);
    if (!bio) return nil;
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cert) return nil;

    NSMutableDictionary *info = [NSMutableDictionary dictionary];
    
    X509_NAME *subjectName = X509_get_subject_name(cert);
    if (subjectName) {
        int idx = X509_NAME_get_index_by_NID(subjectName, NID_commonName, -1);
        if (idx >= 0) {
            ASN1_STRING *data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subjectName, idx));
            unsigned char *utf8 = NULL;
            if (ASN1_STRING_to_UTF8(&utf8, data) > 0 && utf8) {
                [info setObject:[NSString stringWithUTF8String:(char *)utf8] forKey:@"subject"];
                OPENSSL_free(utf8);
            }
        }
    }

    X509_NAME *issuerName = X509_get_issuer_name(cert);
    if (issuerName) {
        int idx = X509_NAME_get_index_by_NID(issuerName, NID_organizationName, -1);
        if (idx >= 0) {
            ASN1_STRING *data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(issuerName, idx));
            unsigned char *utf8 = NULL;
            if (ASN1_STRING_to_UTF8(&utf8, data) > 0 && utf8) {
                [info setObject:[NSString stringWithUTF8String:(char *)utf8] forKey:@"issuer"];
                OPENSSL_free(utf8);
            }
        }
    }

    X509_free(cert);
    return info;
}

- (BOOL)importProfileFromPEMAtPath:(NSString *)path serverAddress:(NSString *)serverAddress {
    return [self importProfileFromPEMAtPath:path serverAddress:serverAddress profileIndex:[self activeProfileIndex]];
}

- (BOOL)importProfileFromPEMAtPath:(NSString *)path serverAddress:(NSString *)serverAddress profileIndex:(NSInteger)index {
    if (!path || path.length == 0) return NO;
    if (!serverAddress || serverAddress.length == 0) return NO;
    if (index < 1 || index > 5) return NO;

    NSFileManager *fm = [NSFileManager defaultManager];

    NSString *destDir = SGPath(@"/var/mobile/Library/SkyglowNotifications");
    if (![fm fileExistsAtPath:destDir]) {
        NSError *mkErr = nil;
        if (![fm createDirectoryAtPath:destDir
           withIntermediateDirectories:YES
                            attributes:nil
                                 error:&mkErr]) {
            return NO;
        }
    }

    NSString *destPath = [destDir stringByAppendingPathComponent:@"server.pem"];
    if ([fm fileExistsAtPath:destPath]) {
        [fm removeItemAtPath:destPath error:nil];
    }
    NSError *copyErr = nil;
    if (![fm copyItemAtPath:path toPath:destPath error:&copyErr]) {
        return NO;
    }

    NSError *readErr = nil;
    NSString *pemString = [NSString stringWithContentsOfFile:destPath
                                                    encoding:NSUTF8StringEncoding
                                                       error:&readErr];
    if (!pemString || pemString.length == 0 ||
        [pemString rangeOfString:@"BEGIN"].location == NSNotFound) {
        [fm removeItemAtPath:destPath error:nil];
        return NO;
    }

    NSString *storedPath = @"/var/mobile/Library/SkyglowNotifications/server.pem";

    NSMutableDictionary *profile = [NSMutableDictionary dictionary];
    [profile setObject:serverAddress forKey:@"server_address"];
    [profile setObject:storedPath    forKey:@"server_pub_key"];

    return [profile writeToFile:SGProfilePathForIndex(index) atomically:YES];
}

#pragma mark - Certificate Auto-Fetch

static void SNAutoFetch_DNSCallback(DNSServiceRef sdRef, DNSServiceFlags flags,
                                    uint32_t interfaceIndex, DNSServiceErrorType errorCode,
                                    const char *fullname, uint16_t rrtype, uint16_t rrclass,
                                    uint16_t rdlen, const void *rdata, uint32_t ttl, void *context) {
    NSMutableDictionary *out = (__bridge NSMutableDictionary *)context;
    if (errorCode != kDNSServiceErr_NoError || rdlen == 0) return;

    const uint8_t *ptr = (const uint8_t *)rdata;
    const uint8_t *end = ptr + rdlen;
    while (ptr < end) {
        uint8_t len = *ptr++;
        if (len == 0 || ptr + len > end) break;
        NSString *entry = [[NSString alloc] initWithBytes:ptr length:len encoding:NSUTF8StringEncoding];
        for (NSString *comp in [entry componentsSeparatedByCharactersInSet:
                                [NSCharacterSet whitespaceCharacterSet]]) {
            NSRange r = [comp rangeOfString:@"="];
            if (r.location != NSNotFound) {
                out[[comp substringToIndex:r.location]] = [comp substringFromIndex:r.location + 1];
            }
        }
        ptr += len;
    }
}

static NSDictionary *SNAutoFetch_LookupTXT(NSString *dnsName) {
    NSMutableDictionary *results = [NSMutableDictionary dictionary];
    DNSServiceRef sdRef = NULL;
    if (DNSServiceQueryRecord(&sdRef, 0, 0, [dnsName UTF8String],
                              kDNSServiceType_TXT, kDNSServiceClass_IN,
                              SNAutoFetch_DNSCallback,
                              (__bridge void *)results) != kDNSServiceErr_NoError) {
        return nil;
    }
    int fd = DNSServiceRefSockFD(sdRef);
    if (fd < 0 || fd >= FD_SETSIZE) { DNSServiceRefDeallocate(sdRef); return nil; }

    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:kSNAutoFetchDNSTimeoutSec];
    BOOL done = NO;
    while (!done && [[NSDate date] compare:deadline] == NSOrderedAscending) {
        fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
        struct timeval tv = {1, 0};
        int sel = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (sel > 0 && FD_ISSET(fd, &rfds)) {
            DNSServiceProcessResult(sdRef);
            if (results.count > 0) done = YES;
        } else if (sel < 0 && errno != EINTR) {
            break;
        }
    }
    DNSServiceRefDeallocate(sdRef);
    return results.count > 0 ? results : nil;
}

- (void)fetchServerCertificateForAddress:(NSString *)serverAddress
                              completion:(void (^)(NSString *, NSString *))completion {
    if (!completion) return;
    NSString *addr = [serverAddress stringByTrimmingCharactersInSet:
                      [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (addr.length == 0) {
        completion(nil, @"Enter a server address first.");
        return;
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *dnsName = [@"_sgn." stringByAppendingString:addr];
        NSDictionary *txt = SNAutoFetch_LookupTXT(dnsName);

        if (!txt || !txt[@"http_addr"]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completion(nil, [NSString stringWithFormat:
                    @"No http_addr TXT record found at %@. Make sure your DNS provider "
                    @"is publishing _sgn.%@ TXT with http_addr=…", dnsName, addr]);
            });
            return;
        }

        NSString *httpBase = txt[@"http_addr"];
        if (![httpBase hasPrefix:@"http://"] && ![httpBase hasPrefix:@"https://"]) {
            httpBase = [@"https://" stringByAppendingString:httpBase];
        }
        NSURL *certURL = [NSURL URLWithString:
                          [httpBase stringByAppendingString:kSNAutoFetchCertPath]];
        if (!certURL) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completion(nil, [NSString stringWithFormat:
                    @"Malformed http_addr in TXT record: %@", txt[@"http_addr"]]);
            });
            return;
        }

        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:certURL];
        [req setTimeoutInterval:kSNAutoFetchHTTPTimeoutSec];
        [req setHTTPMethod:@"GET"];

        SNAutoFetchConnectionDelegate *del = [[SNAutoFetchConnectionDelegate alloc] init];
        NSURLConnection *conn = [[NSURLConnection alloc] initWithRequest:req
                                                                 delegate:del
                                                         startImmediately:NO];
        if (!conn) {
            [del release];
            dispatch_async(dispatch_get_main_queue(), ^{
                completion(nil, @"Could not create network connection.");
            });
            return;
        }

        NSRunLoop *rl = [NSRunLoop currentRunLoop];
        [conn scheduleInRunLoop:rl forMode:NSDefaultRunLoopMode];
        [conn start];

        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:kSNAutoFetchHTTPTimeoutSec];
        while (!del.done && [[NSDate date] compare:deadline] == NSOrderedAscending) {
            [rl runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.25]];
        }
        if (!del.done) [conn cancel];

        /* Snapshot results onto autoreleased storage that the main-queue
         * block can safely outlive the delegate/connection cleanup below. */
        NSError   *connErr = [[del.error retain] autorelease];
        NSInteger  code    = del.statusCode;
        NSData    *body    = [[del.buffer retain] autorelease];
        BOOL       timedOut = !del.done && !connErr;

        [conn release];
        [del release];

        dispatch_async(dispatch_get_main_queue(), ^{
            if (timedOut) {
                completion(nil, [NSString stringWithFormat:
                    @"Timed out fetching certificate from %@", [certURL absoluteString]]);
                return;
            }
            if (connErr) {
                completion(nil, [NSString stringWithFormat:
                    @"Cert download failed: %@", [connErr localizedDescription]]);
                return;
            }
            if (code != 200) {
                completion(nil, [NSString stringWithFormat:
                    @"Server responded HTTP %ld at %@", (long)code, [certURL absoluteString]]);
                return;
            }
            NSString *pem = body ? [[[NSString alloc] initWithData:body
                                                          encoding:NSUTF8StringEncoding] autorelease] : nil;
            if (!pem || [pem rangeOfString:@"BEGIN"].location == NSNotFound) {
                completion(nil, @"Server returned data that is not a PEM certificate.");
                return;
            }
            completion(pem, nil);
        });
    });
}

- (BOOL)installFetchedCertificatePEM:(NSString *)pem
                       serverAddress:(NSString *)serverAddress
                        profileIndex:(NSInteger)index {
    if (!pem || pem.length == 0) return NO;
    if (!serverAddress || serverAddress.length == 0) return NO;
    if (index < 1 || index > 5) return NO;

    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *destDir = SGPath(@"/var/mobile/Library/SkyglowNotifications");
    if (![fm fileExistsAtPath:destDir]) {
        if (![fm createDirectoryAtPath:destDir withIntermediateDirectories:YES
                            attributes:nil error:nil]) return NO;
    }

    NSString *destPath = [destDir stringByAppendingPathComponent:@"server.pem"];
    if (![pem writeToFile:destPath atomically:YES
                  encoding:NSUTF8StringEncoding error:nil]) return NO;

    NSMutableDictionary *profile = [NSMutableDictionary dictionary];
    profile[@"server_address"] = serverAddress;
    profile[@"server_pub_key"] = @"/var/mobile/Library/SkyglowNotifications/server.pem";
    return [profile writeToFile:SGProfilePathForIndex(index) atomically:YES];
}

- (void)unregisterDevice {
    [self unregisterProfileAtIndex:[self activeProfileIndex]];
}

- (void)unregisterProfileAtIndex:(NSInteger)index {
    [self deleteProfileAtIndex:index];

    sqlite3 *db = NULL;
    if (sqlite3_open([SGDBPath() UTF8String], &db) == SQLITE_OK) {
        sqlite3_exec(db, "DELETE FROM notifications;", NULL, NULL, NULL);
        sqlite3_exec(db, "DELETE FROM dns_cache;", NULL, NULL, NULL);
    }
    if (db) sqlite3_close(db);
}

#pragma mark - Multi-Profile API

- (NSInteger)activeProfileIndex {
    NSDictionary *prefs = [self mainPrefs];
    NSNumber *num = [prefs objectForKey:@"activeProfile"];
    return (num && [num integerValue] >= 1 && [num integerValue] <= 5) ? [num integerValue] : 1;
}

- (void)setActiveProfileIndex:(NSInteger)index {
    if (index < 1 || index > 5) return;
    [self setMainPrefValue:@(index) forKey:@"activeProfile"];
}

- (NSString *)profilePathForIndex:(NSInteger)index {
    return SGProfilePathForIndex(index);
}

- (NSDictionary *)profileForIndex:(NSInteger)index {
    return [NSDictionary dictionaryWithContentsOfFile:SGProfilePathForIndex(index)] ?: @{};
}

- (BOOL)profileExistsAtIndex:(NSInteger)index {
    return [[NSFileManager defaultManager] fileExistsAtPath:SGProfilePathForIndex(index)];
}

- (BOOL)deleteProfileAtIndex:(NSInteger)index {
    if (index < 1 || index > 5) return NO;
    NSString *profilePath = SGProfilePathForIndex(index);
    NSDictionary *profile = [NSDictionary dictionaryWithContentsOfFile:profilePath];

    NSString *privKeyPath = [profile objectForKey:@"privateKey"];
    if (privKeyPath) {
        [[NSFileManager defaultManager] removeItemAtPath:SGPath(privKeyPath) error:nil];
    }

    return [[NSFileManager defaultManager] removeItemAtPath:profilePath error:nil];
}

- (NSString *)hexStringFromData:(NSData *)data {
    if (!data || [data length] == 0) return @"";
    const unsigned char *bytes = (const unsigned char *)[data bytes];
    NSMutableString *hex = [NSMutableString stringWithCapacity:([data length] * 2)];
    for (NSUInteger i = 0; i < [data length]; i++) [hex appendFormat:@"%02x", bytes[i]];
    return hex;
}

- (NSString *)friendlyStringForState:(SGState)state {
    switch (state) {
        case SGStateConnected:         return @"Connected";
        case SGStateAuthenticating:    return @"Authenticating…";
        case SGStateConnecting:        return @"Connecting…";
        case SGStateResolvingDNS:      return @"Resolving DNS…";
        case SGStateBackingOff:        return @"Reconnecting…";
        case SGStateIdleNoNetwork:     return @"No Network";
        case SGStateIdleDNSFailed:     return @"DNS Failed";
        case SGStateIdleCircuitOpen:   return @"Paused (Too Many Errors)";
        case SGStateIdleUnregistered:  return @"Waiting for Config";
        case SGStateDisabled:          return @"Disabled";
        case SGStateErrorAuth:         return @"Auth Error";
        case SGStateErrorBadConfig:    return @"Bad Config";
        case SGStateError:             return @"Error";
        case SGStateStarting:          return @"Starting…";
        case SGStateShuttingDown:      return @"Shutting Down";
        case SGStateRegistering:       return @"Registering…";
        default:                       return @"Unknown";
    }
}

- (UIColor *)colorForState:(SGState)state {
    switch (state) {
        case SGStateConnected: return [UIColor colorWithRed:0.2 green:0.7 blue:0.2 alpha:1.0];
        case SGStateConnecting: case SGStateAuthenticating: case SGStateResolvingDNS: case SGStateBackingOff: case SGStateRegistering: return [UIColor orangeColor];
        case SGStateIdleNoNetwork: case SGStateIdleCircuitOpen: case SGStateIdleDNSFailed: return [UIColor colorWithRed:0.9 green:0.6 blue:0.1 alpha:1.0];
        case SGStateErrorAuth: case SGStateErrorBadConfig: case SGStateError: return [UIColor colorWithRed:0.85 green:0.2 blue:0.2 alpha:1.0];
        default: return [UIColor grayColor];
    }
}

- (NSString *)recoverySuggestionForState:(SGState)state {
    switch (state) {
        case SGStateErrorAuth:
            return @"Try re-importing your server certificate.";
        case SGStateErrorBadConfig:
            return @"Check your server address and certificate in profile settings.";
        case SGStateIdleDNSFailed:
            return @"Check your server address or DNS settings.";
        case SGStateIdleCircuitOpen:
            return @"The daemon will retry on network change, or restart it manually.";
        case SGStateError:
            return @"Try restarting the daemon from Debug Tools.";
        case SGStateIdleNoNetwork:
            return @"Check your Wi-Fi or cellular connection.";
        default:
            return nil;
    }
}

@end
