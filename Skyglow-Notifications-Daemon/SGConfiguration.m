#import "SGConfiguration.h"
#import "SGKeychainStore.h"
#import "SGLog.h"

/* Scrubs a private-key buffer before releasing it so the PEM never lingers in
 * freed heap memory. */
static void SG_ZeroAndReleaseData(NSMutableData *data) {
    if (!data) return;
    [data resetBytesInRange:NSMakeRange(0, [data length])];
    [data release];
}

@implementation SGConfiguration {
    NSString *_serverAddress;
    NSString *_serverIPAddress;
    NSString *_serverPort;

    BOOL _isEnabled;
    BOOL _hasProfile;
    NSString *_deviceAddress;
    NSMutableData *_privateKeyPEM;
    NSString *_serverPubKeyPEM;
    NSInteger _activeProfileIndex;
    NSInteger _logLevel;

    dispatch_queue_t _isolationQueue;
}

+ (SGConfiguration *)sharedConfiguration {
    static SGConfiguration *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[self alloc] init];
    });
    return sharedInstance;
}

- (id)init {
    if ((self = [super init])) {
        _isolationQueue = dispatch_queue_create("com.skyglow.configuration.queue", DISPATCH_QUEUE_CONCURRENT);
        [self reloadFromDisk];
    }
    return self;
}

- (void)reloadFromDisk {
    NSString *mainPath = SGPath(SG_PREFS_PLIST_PATH);
    NSDictionary *mainPrefs = [NSDictionary dictionaryWithContentsOfFile:mainPath];

    BOOL nextEnabled = mainPrefs ? [mainPrefs[@"enabled"] boolValue] : NO;

    NSNumber *profileNum = mainPrefs ? mainPrefs[@"activeProfile"] : nil;
    NSInteger nextActiveProfileIndex =
        (profileNum && [profileNum integerValue] >= 1 && [profileNum integerValue] <= 5)
            ? [profileNum integerValue] : 1;

    NSNumber *logLevelNum = mainPrefs ? mainPrefs[@"logLevel"] : nil;
    NSInteger nextLogLevel = logLevelNum ? [logLevelNum integerValue] : 2;
    if (nextLogLevel < 0 || nextLogLevel > 4) nextLogLevel = 2;

    BOOL nextHasProfile = NO;
    NSString *nextServerAddress = nil;
    NSString *nextDeviceAddress = nil;
    NSMutableData *nextPrivateKeyPEM = nil;
    NSString *nextServerPubKeyPEM = nil;

    NSString *profilePath = SGPath([NSString stringWithFormat:
        SG_PROFILE_PLIST_FORMAT, (long)nextActiveProfileIndex]);
    NSDictionary *profilePrefs = [NSDictionary dictionaryWithContentsOfFile:profilePath];
    if (profilePrefs) {
        nextHasProfile = YES;
        nextServerAddress = [profilePrefs[@"server_address"] copy];
        nextDeviceAddress = [profilePrefs[@"device_address"] copy];
        nextPrivateKeyPEM = [SGKeychain_FetchPrivateKeyPEM(nextActiveProfileIndex) mutableCopy];
        nextServerPubKeyPEM = [[self readKeyFromFile:profilePrefs[@"server_pub_key"]] copy];
    }

    dispatch_barrier_sync(_isolationQueue, ^{
        self->_isEnabled = nextEnabled;
        self->_activeProfileIndex = nextActiveProfileIndex;
        self->_logLevel = nextLogLevel;
        self->_hasProfile = nextHasProfile;

        [self->_serverAddress release];
        self->_serverAddress = nextServerAddress;
        [self->_deviceAddress release];
        self->_deviceAddress = nextDeviceAddress;
        SG_ZeroAndReleaseData(self->_privateKeyPEM);
        self->_privateKeyPEM = nextPrivateKeyPEM;
        [self->_serverPubKeyPEM release];
        self->_serverPubKeyPEM = nextServerPubKeyPEM;

        [self->_serverIPAddress release];
        self->_serverIPAddress = nil;
        [self->_serverPort release];
        self->_serverPort = nil;
    });
}

- (NSString *)readKeyFromFile:(NSString *)rawPath {
    if (!rawPath || [rawPath length] == 0) return nil;
    
    if ([rawPath length] > 1024) {
        SGLOGE(SGConfiguration, "code=%s result=failed length=%lu max=1024", SGND_CONFIG_KEY_PATH_TOO_LONG, (unsigned long)[rawPath length]);
        return nil;
    }

    NSString *safePath = SGPath(rawPath);

    BOOL isDirectory = NO;
    if (![[NSFileManager defaultManager] fileExistsAtPath:safePath isDirectory:&isDirectory] || isDirectory) {
        SGLOGW(SGConfiguration, "code=%s path=%s result=missing", SGND_CONFIG_KEY_MISSING, [safePath UTF8String]);
        return nil;
    }

    NSError *attrError = nil;
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:safePath error:&attrError];
    if (attrError || !attrs) {
        SGLOGW(SGConfiguration, "code=%s path=%s result=failed", SGND_CONFIG_KEY_STAT_FAILED, [safePath UTF8String]);
        return nil;
    }

    unsigned long long fileSize = [attrs fileSize];
    if (fileSize > 65536) {
        SGLOGE(SGConfiguration, "code=%s path=%s bytes=%llu max=65536 result=failed", SGND_CONFIG_KEY_TOO_LARGE,
                    [safePath UTF8String], fileSize);
        return nil;
    }

    NSError *readError = nil;
    NSString *keyContent = [NSString stringWithContentsOfFile:safePath encoding:NSUTF8StringEncoding error:&readError];

    if (readError || !keyContent) {
        SGLOGW(SGConfiguration, "code=%s path=%s result=failed", SGND_CONFIG_KEY_READ_FAILED, [safePath UTF8String]);
        return nil;
    }
    
    return keyContent;
}

- (BOOL)isValid {
    __block BOOL valid = NO;
    dispatch_sync(_isolationQueue, ^{
        if (!self->_hasProfile) {
            return;
        }

        if (!self->_serverAddress || [self->_serverAddress length] == 0) {
            return;
        }
        
        if (!self->_serverPubKeyPEM || [self->_serverPubKeyPEM length] == 0) {
            return;
        }
        
        valid = YES;
    });
    return valid;
}

- (void)dealloc {
    [_serverAddress release];
    [_serverIPAddress release];
    [_serverPort release];
    [_deviceAddress release];
    SG_ZeroAndReleaseData(_privateKeyPEM);
    [_serverPubKeyPEM release];
    if (_isolationQueue) dispatch_release(_isolationQueue);
    [super dealloc];
}

- (NSString *)serverAddress {
    __block NSString *result = nil;
    dispatch_sync(_isolationQueue, ^{
        result = [self->_serverAddress retain];
    });
    return [result autorelease];
}

- (void)setServerIPAddress:(NSString *)ip {
    dispatch_barrier_sync(_isolationQueue, ^{
        if (self->_serverIPAddress != ip) {
            [self->_serverIPAddress release];
            self->_serverIPAddress = [ip copy];
        }
    });
}

- (NSString *)serverIPAddress {
    __block NSString *result = nil;
    dispatch_sync(_isolationQueue, ^{
        result = [self->_serverIPAddress retain];
    });
    return [result autorelease];
}

- (void)setServerPort:(NSString *)port {
    dispatch_barrier_sync(_isolationQueue, ^{
        if (self->_serverPort != port) {
            [self->_serverPort release];
            self->_serverPort = [port copy];
        }
    });
}

- (NSString *)serverPort {
    __block NSString *result = nil;
    dispatch_sync(_isolationQueue, ^{
        result = [self->_serverPort retain];
    });
    return [result autorelease];
}

- (BOOL)isEnabled {
    __block BOOL result = NO;
    dispatch_sync(_isolationQueue, ^{
        result = self->_isEnabled;
    });
    return result;
}

- (BOOL)hasProfile {
    __block BOOL result = NO;
    dispatch_sync(_isolationQueue, ^{
        result = self->_hasProfile;
    });
    return result;
}

- (NSString *)deviceAddress {
    __block NSString *result = nil;
    dispatch_sync(_isolationQueue, ^{
        result = [self->_deviceAddress retain];
    });
    return [result autorelease];
}

- (NSData *)privateKeyPEM {
    __block NSData *result = nil;
    dispatch_sync(_isolationQueue, ^{
        if (self->_privateKeyPEM) {
            result = [[NSData alloc] initWithData:self->_privateKeyPEM];
        }
    });
    return [result autorelease];
}

- (NSString *)serverPubKeyPEM {
    __block NSString *result = nil;
    dispatch_sync(_isolationQueue, ^{
        result = [self->_serverPubKeyPEM retain];
    });
    return [result autorelease];
}

- (NSInteger)activeProfileIndex {
    __block NSInteger result = 1;
    dispatch_sync(_isolationQueue, ^{
        result = self->_activeProfileIndex;
    });
    return result;
}

- (NSInteger)logLevel {
    __block NSInteger result = 2;
    dispatch_sync(_isolationQueue, ^{
        result = self->_logLevel;
    });
    return result;
}

@end
