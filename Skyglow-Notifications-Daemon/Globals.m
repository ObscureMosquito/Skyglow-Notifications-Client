#import "Globals.h"

DBManager *db = nil;

// Private storage
static NSString *_serverAddress = nil;
static NSString *_serverIPString = nil;
static NSString *_serverPortString = nil;

// A concurrent queue allows multiple threads to read simultaneously,
// but blocks reads when a write (barrier) is occurring.
static dispatch_queue_t getConfigQueue() {
    static dispatch_queue_t queue = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        queue = dispatch_queue_create("com.skyglow.configQueue", DISPATCH_QUEUE_CONCURRENT);
    });
    return queue;
}

// -- Server Address --
void SetServerAddress(NSString *address) {
    dispatch_barrier_async(getConfigQueue(), ^{
        if (_serverAddress != address) {
            [_serverAddress release];
            _serverAddress = [address copy];
        }
    });
}

NSString *GetServerAddress(void) {
    __block NSString *result = nil;
    dispatch_sync(getConfigQueue(), ^{
        result = [_serverAddress retain]; // Retain to ensure safety for caller
    });
    return [result autorelease];
}

// -- Server IP String --
void SetServerIPString(NSString *ip) {
    dispatch_barrier_async(getConfigQueue(), ^{
        if (_serverIPString != ip) {
            [_serverIPString release];
            _serverIPString = [ip copy];
        }
    });
}

NSString *GetServerIPString(void) {
    __block NSString *result = nil;
    dispatch_sync(getConfigQueue(), ^{
        result = [_serverIPString retain];
    });
    return [result autorelease];
}

// -- Server Port String --
void SetServerPortString(NSString *port) {
    dispatch_barrier_async(getConfigQueue(), ^{
        if (_serverPortString != port) {
            [_serverPortString release];
            _serverPortString = [port copy];
        }
    });
}

NSString *GetServerPortString(void) {
    __block NSString *result = nil;
    dispatch_sync(getConfigQueue(), ^{
        result = [_serverPortString retain];
    });
    return [result autorelease];
}