#import "SGConfiguration.h"

@implementation SGConfiguration {
    NSString *_serverAddress;
    NSString *_serverIPAddress;
    NSString *_serverPort;
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
    }
    return self;
}

- (void)dealloc {
    [_serverAddress release];
    [_serverIPAddress release];
    [_serverPort release];
    if (_isolationQueue) dispatch_release(_isolationQueue);
    [super dealloc];
}

// ── Thread-Safe Property Accessors ─────────────────────────────────

- (void)setServerAddress:(NSString *)address {
    dispatch_barrier_async(_isolationQueue, ^{
        if (_serverAddress != address) {
            [_serverAddress release];
            _serverAddress = [address copy];
        }
    });
}

- (NSString *)serverAddress {
    __block NSString *result = nil;
    dispatch_sync(_isolationQueue, ^{
        result = [_serverAddress retain];
    });
    return [result autorelease];
}

- (void)setServerIPAddress:(NSString *)ip {
    dispatch_barrier_async(_isolationQueue, ^{
        if (_serverIPAddress != ip) {
            [_serverIPAddress release];
            _serverIPAddress = [ip copy];
        }
    });
}

- (NSString *)serverIPAddress {
    __block NSString *result = nil;
    dispatch_sync(_isolationQueue, ^{
        result = [_serverIPAddress retain];
    });
    return [result autorelease];
}

- (void)setServerPort:(NSString *)port {
    dispatch_barrier_async(_isolationQueue, ^{
        if (_serverPort != port) {
            [_serverPort release];
            _serverPort = [port copy];
        }
    });
}

- (NSString *)serverPort {
    __block NSString *result = nil;
    dispatch_sync(_isolationQueue, ^{
        result = [_serverPort retain];
    });
    return [result autorelease];
}

@end