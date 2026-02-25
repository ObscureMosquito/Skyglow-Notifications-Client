#import "SGConfiguration.h"

// SGPath() is defined in SGConfiguration.h

@implementation SGConfiguration {
    NSString *_serverAddress;
    NSString *_serverIPAddress;
    NSString *_serverPort;
    
    BOOL _isEnabled;
    BOOL _hasProfile;
    NSString *_deviceAddress;
    NSString *_privateKeyPEM;
    NSString *_serverPubKeyPEM;
    
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
    dispatch_barrier_sync(_isolationQueue, ^{
        NSString *mainPath = SGPath(@"/var/mobile/Library/Preferences/com.skyglow.sndp.plist");
        NSDictionary *mainPrefs = [NSDictionary dictionaryWithContentsOfFile:mainPath];
        if (mainPrefs) {
            self->_isEnabled = [mainPrefs[@"enabled"] boolValue];
        } else {
            self->_isEnabled = NO;
        }
        
        NSString *profilePath = SGPath(@"/var/mobile/Library/Preferences/com.skyglow.sndp-profile1.plist");
        NSDictionary *profilePrefs = [NSDictionary dictionaryWithContentsOfFile:profilePath];
        if (profilePrefs) {
            self->_hasProfile = YES;
            NSString *addr = profilePrefs[@"server_address"];
            if (self->_serverAddress != addr) {
                [self->_serverAddress release];
                self->_serverAddress = [addr copy];
            }
            
            NSString *devAddr = profilePrefs[@"device_address"];
            if (self->_deviceAddress != devAddr) {
                [self->_deviceAddress release];
                self->_deviceAddress = [devAddr copy];
            }
            
            NSString *privKeyPath = profilePrefs[@"privateKey"];
            NSString *privKey = [self readKeyFromFile:privKeyPath];
            if (self->_privateKeyPEM != privKey) {
                [self->_privateKeyPEM release];
                self->_privateKeyPEM = [privKey copy];
            }
            
            NSString *pubKeyPath = profilePrefs[@"server_pub_key"];
            NSString *pubKey = [self readKeyFromFile:pubKeyPath];
            if (self->_serverPubKeyPEM != pubKey) {
                [self->_serverPubKeyPEM release];
                self->_serverPubKeyPEM = [pubKey copy];
            }
        } else {
            self->_hasProfile = NO;
        }
    });
}

- (NSString *)readKeyFromFile:(NSString *)rawPath {
    if (!rawPath || [rawPath length] == 0) return nil;
    
    if ([rawPath length] > 1024) {
        NSLog(@"[SGConfiguration] ABORT: Provided path string exceeds PATH_MAX. Is this a raw PEM?");
        return nil;
    }
    
    NSString *safePath = SGPath(rawPath);
    
    BOOL isDirectory = NO;
    if (![[NSFileManager defaultManager] fileExistsAtPath:safePath isDirectory:&isDirectory] || isDirectory) {
        NSLog(@"[SGConfiguration] Key file or its directory are missing");
        return nil;
    }
    
    NSError *attrError = nil;
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:safePath error:&attrError];
    if (attrError || !attrs) {
        NSLog(@"[SGConfiguration] Cannot stat key file attributes");
        return nil;
    }
    
    unsigned long long fileSize = [attrs fileSize];
    if (fileSize > 65536) {
        NSLog(@"[SGConfiguration] ABORT: Key file exceeds 64KB safety limit!");
        return nil;
    }
    
    NSError *readError = nil;
    NSString *keyContent = [NSString stringWithContentsOfFile:safePath encoding:NSUTF8StringEncoding error:&readError];
    
    if (readError || !keyContent) {
        NSLog(@"[SGConfiguration] Failed to read key file");
        return nil;
    }
    
    return keyContent;
}

// Add this alongside your other property accessors
- (BOOL)isValid {
    __block BOOL valid = NO;
    dispatch_sync(_isolationQueue, ^{
        if (!self->_serverAddress || [self->_serverAddress length] == 0) {
            return;
        }
        
        if (self->_hasProfile && (!self->_serverPubKeyPEM || [self->_serverPubKeyPEM length] == 0)) {
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
    [_privateKeyPEM release];
    [_serverPubKeyPEM release];
    if (_isolationQueue) dispatch_release(_isolationQueue);
    [super dealloc];
}

// ── Thread-Safe Property Accessors ─────────────────────────────────

- (void)setServerAddress:(NSString *)address {
    dispatch_barrier_async(_isolationQueue, ^{
        if (self->_serverAddress != address) {
            [self->_serverAddress release];
            self->_serverAddress = [address copy];
        }
    });
}

- (NSString *)serverAddress {
    __block NSString *result = nil;
    dispatch_sync(_isolationQueue, ^{
        result = [self->_serverAddress retain];
    });
    return [result autorelease];
}

- (void)setServerIPAddress:(NSString *)ip {
    dispatch_barrier_async(_isolationQueue, ^{
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
    dispatch_barrier_async(_isolationQueue, ^{
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

- (void)setIsEnabled:(BOOL)enabled {
    dispatch_barrier_async(_isolationQueue, ^{
        self->_isEnabled = enabled;
    });
}

- (BOOL)isEnabled {
    __block BOOL result = NO;
    dispatch_sync(_isolationQueue, ^{
        result = self->_isEnabled;
    });
    return result;
}

- (void)setHasProfile:(BOOL)hasProfile {
    dispatch_barrier_async(_isolationQueue, ^{
        self->_hasProfile = hasProfile;
    });
}

- (BOOL)hasProfile {
    __block BOOL result = NO;
    dispatch_sync(_isolationQueue, ^{
        result = self->_hasProfile;
    });
    return result;
}

- (void)setDeviceAddress:(NSString *)address {
    dispatch_barrier_async(_isolationQueue, ^{
        if (self->_deviceAddress != address) {
            [self->_deviceAddress release];
            self->_deviceAddress = [address copy];
        }
    });
}

- (NSString *)deviceAddress {
    __block NSString *result = nil;
    dispatch_sync(_isolationQueue, ^{
        result = [self->_deviceAddress retain];
    });
    return [result autorelease];
}

- (void)setPrivateKeyPEM:(NSString *)pem {
    dispatch_barrier_async(_isolationQueue, ^{
        if (self->_privateKeyPEM != pem) {
            [self->_privateKeyPEM release];
            self->_privateKeyPEM = [pem copy];
        }
    });
}

- (NSString *)privateKeyPEM {
    __block NSString *result = nil;
    dispatch_sync(_isolationQueue, ^{
        result = [self->_privateKeyPEM retain];
    });
    return [result autorelease];
}

- (void)setServerPubKeyPEM:(NSString *)pem {
    dispatch_barrier_async(_isolationQueue, ^{
        if (self->_serverPubKeyPEM != pem) {
            [self->_serverPubKeyPEM release];
            self->_serverPubKeyPEM = [pem copy];
        }
    });
}

- (NSString *)serverPubKeyPEM {
    __block NSString *result = nil;
    dispatch_sync(_isolationQueue, ^{
        result = [self->_serverPubKeyPEM retain];
    });
    return [result autorelease];
}

@end