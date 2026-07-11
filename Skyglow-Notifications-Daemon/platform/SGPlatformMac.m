#ifndef OS_OBJECT_USE_OBJC
#define OS_OBJECT_USE_OBJC 0
#endif

#import "SGPlatform.h"

#if TARGET_OS_OSX

#import <xpc/xpc.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import "SGControlChannelProtocol.h"

extern mach_port_t bootstrap_port;
extern kern_return_t bootstrap_look_up_per_user(mach_port_t, const char *, uid_t, mach_port_t *);
typedef xpc_object_t (*SGEndpointFromPortFn)(mach_port_t);

static const char *const kUsernotedService = "com.apple.usernoted.client";

static void SGCloseConnection(xpc_connection_t conn) {
    xpc_connection_set_event_handler(conn, ^(xpc_object_t event) { (void)event; });
    xpc_connection_cancel(conn);
    xpc_release(conn);
}

@interface SGUNArchiveShim : NSObject <NSCoding>

@property (nonatomic, copy) NSString *sgTitle, *sgSubtitle, *sgBody, *sgSound;

@end

@implementation SGUNArchiveShim
- (void)encodeWithCoder:(NSCoder *)c {
    if (_sgTitle)    [c encodeObject:_sgTitle    forKey:@"NSTitle"];
    if (_sgSubtitle) [c encodeObject:_sgSubtitle forKey:@"NSSubtitle"];
    if (_sgBody)     [c encodeObject:_sgBody     forKey:@"NSInformativetext"];
    if (_sgSound)    [c encodeObject:_sgSound    forKey:@"NSSoundname"];
    [c encodeInt:1 forKey:@"NSEncodedVersion"];
}
- (instancetype)initWithCoder:(NSCoder *)c { return [super init]; }
- (void)dealloc {
    [_sgTitle release]; [_sgSubtitle release]; [_sgBody release]; [_sgSound release];
    [super dealloc];
}
@end

@implementation SGPlatform {
    dispatch_queue_t _cacheQueue;
    NSMutableDictionary *_conns;
    NSMutableDictionary *_endpoints;
    uid_t _connsUID;
    BOOL _haveConnsUID;
    SGEndpointFromPortFn _endpointFn;
    BOOL _resolvedEndpointFn;
}

#pragma mark - Lifecycle

- (instancetype)initWithDeliveryReadyHandler:(void (^)(void))handler {
    (void)handler;
    if ((self = [super init])) {
        _conns = [[NSMutableDictionary alloc] init];
        _endpoints = [[NSMutableDictionary alloc] init];
        _cacheQueue = dispatch_queue_create("com.skyglow.daemon.usernoted", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (BOOL)start { return YES; }
- (void)stop { dispatch_sync(_cacheQueue, ^{ [self _closeAll]; }); }

- (void)dealloc {
    [self stop];
    dispatch_release(_cacheQueue);
    [_conns release];
    [_endpoints release];
    [super dealloc];
}

#pragma mark - usernoted archive + envelope

- (NSData *)_archiveTitle:(NSString *)title subtitle:(NSString *)subtitle
                     body:(NSString *)body sound:(NSString *)sound {
    SGUNArchiveShim *n = [[[SGUNArchiveShim alloc] init] autorelease];
    n.sgTitle = title; n.sgSubtitle = subtitle; n.sgBody = body; n.sgSound = sound;

    NSKeyedArchiver *archiver;
    NSMutableData *backing = nil;
    if ([NSKeyedArchiver instancesRespondToSelector:@selector(initRequiringSecureCoding:)]) {
        archiver = [[NSKeyedArchiver alloc] initRequiringSecureCoding:NO];   // 10.13+
    } else {
        backing = [NSMutableData data];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        archiver = [[NSKeyedArchiver alloc] initForWritingWithMutableData:backing];
#pragma clang diagnostic pop
    }
    [archiver setClassName:@"_NSConcreteUserNotification" forClass:[SGUNArchiveShim class]];
    [archiver encodeObject:n forKey:@"root"];
    [archiver finishEncoding];
    NSData *result = [[(backing ? backing : [archiver encodedData]) retain] autorelease];
    [archiver release];
    return result;
}

- (xpc_object_t)_newHandshake:(NSString *)bundleID {
    xpc_object_t hs = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_int64 (hs, "center_type", 0);
    xpc_dictionary_set_bool  (hs, "system_originated", false);
    xpc_dictionary_set_uint64(hs, "message_type", 1);
    xpc_dictionary_set_bool  (hs, "app_originated", true);
    xpc_dictionary_set_string(hs, "bundle_identifier", [bundleID UTF8String]);
    return hs;
}

- (xpc_object_t)_newDeliver:(NSData *)archive {
    xpc_object_t dv = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(dv, "message_type", 3);
    xpc_dictionary_set_bool  (dv, "immediate", true);
    xpc_dictionary_set_data  (dv, "encoded_notification", [archive bytes], [archive length]);
    return dv;
}

#pragma mark - Per-user connection cache

+ (uid_t)_consoleUID {
    uid_t uid = (uid_t)-1;
    CFStringRef name = SCDynamicStoreCopyConsoleUser(NULL, &uid, NULL);
    if (!name) return (uid_t)-1;
    BOOL none = (CFStringGetLength(name) == 0) ||
                (CFStringCompare(name, CFSTR("loginwindow"), 0) == kCFCompareEqualTo);
    CFRelease(name);
    return (none || uid == 0) ? (uid_t)-1 : uid;
}

- (SGEndpointFromPortFn)_endpointFn {
    if (!_resolvedEndpointFn) {
        _resolvedEndpointFn = YES;
        _endpointFn = (SGEndpointFromPortFn)dlsym(RTLD_DEFAULT, "_xpc_endpoint_create_bs_from_port");
        if (!_endpointFn)
            _endpointFn = (SGEndpointFromPortFn)dlsym(RTLD_DEFAULT, "xpc_endpoint_create_bs_from_port");
    }
    return _endpointFn;
}

- (xpc_connection_t)_newConnForUID:(uid_t)targetUID endpointOut:(xpc_object_t *)endpointOut {
    if (endpointOut) *endpointOut = NULL;
    if (geteuid() == targetUID)
        return xpc_connection_create_mach_service(kUsernotedService, NULL, 0);

    mach_port_t port = MACH_PORT_NULL;
    if (bootstrap_look_up_per_user(bootstrap_port, kUsernotedService, targetUID, &port) != KERN_SUCCESS
        || port == MACH_PORT_NULL) return NULL;
    SGEndpointFromPortFn fn = [self _endpointFn];
    if (!fn) return NULL;
    xpc_object_t endpoint = fn(port);
    if (!endpoint) return NULL;
    xpc_connection_t conn = xpc_connection_create_from_endpoint((xpc_endpoint_t)endpoint);
    if (!conn) { xpc_release(endpoint); return NULL; }
    if (endpointOut) *endpointOut = endpoint; else xpc_release(endpoint);
    return conn;
}

- (xpc_connection_t)_connForBundle:(NSString *)bundleID {
    uid_t uid = [[self class] _consoleUID];
    if (uid == (uid_t)-1) return NULL;
    if (!_haveConnsUID || uid != _connsUID) { [self _closeAll]; _connsUID = uid; _haveConnsUID = YES; }

    NSValue *boxed = [_conns objectForKey:bundleID];
    if (boxed) return (xpc_connection_t)[boxed pointerValue];

    xpc_object_t endpoint = NULL;
    xpc_connection_t conn = [self _newConnForUID:uid endpointOut:&endpoint];
    if (!conn) return NULL;

    __unsafe_unretained SGPlatform *uself = self;
    dispatch_queue_t cacheQueue = _cacheQueue;
    NSString *bundleCopy = [[bundleID copy] autorelease];
    xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
        if (xpc_get_type(event) == XPC_TYPE_ERROR)
            dispatch_async(cacheQueue, ^{ [uself _dropBundle:bundleCopy]; });
    });
    xpc_connection_resume(conn);

    xpc_object_t hs = [self _newHandshake:bundleID];
    xpc_connection_send_message(conn, hs);
    xpc_release(hs);

    [_conns setObject:[NSValue valueWithPointer:conn] forKey:bundleID];
    if (endpoint) [_endpoints setObject:[NSValue valueWithPointer:endpoint] forKey:bundleID];
    return conn;
}

- (void)_dropBundle:(NSString *)bundleID {
    NSValue *boxed = [_conns objectForKey:bundleID];
    if (boxed) {
        SGCloseConnection((xpc_connection_t)[boxed pointerValue]);
        [_conns removeObjectForKey:bundleID];
    }
    NSValue *ep = [_endpoints objectForKey:bundleID];
    if (ep) { xpc_release((xpc_object_t)[ep pointerValue]); [_endpoints removeObjectForKey:bundleID]; }
}

- (void)_closeAll {
    for (NSValue *b in [_conns allValues]) SGCloseConnection((xpc_connection_t)[b pointerValue]);
    [_conns removeAllObjects];
    for (NSValue *ep in [_endpoints allValues]) xpc_release((xpc_object_t)[ep pointerValue]);
    [_endpoints removeAllObjects];
}

#pragma mark - Delivery

- (kern_return_t)sendNotificationForBundleID:(NSString *)bundleID payload:(NSDictionary *)payload {
    if (![bundleID isKindOfClass:[NSString class]] || bundleID.length == 0) return KERN_INVALID_ARGUMENT;

    NSDictionary *aps = payload;
    id inner = [payload objectForKey:@"aps"];
    if ([inner isKindOfClass:[NSDictionary class]]) aps = inner;

    NSString *title = nil, *subtitle = nil, *body = nil, *sound = nil;
    id alert = [aps objectForKey:@"alert"];
    if ([alert isKindOfClass:[NSString class]]) body = alert;
    else if ([alert isKindOfClass:[NSDictionary class]]) {
        title = [alert objectForKey:@"title"];
        subtitle = [alert objectForKey:@"subtitle"];
        body = [alert objectForKey:@"body"];
    }
    id apsSound = [aps objectForKey:@"sound"];
    if ([apsSound isKindOfClass:[NSString class]]) sound = apsSound;
    else if ([apsSound isKindOfClass:[NSDictionary class]]) {
        id nm = [apsSound objectForKey:@"name"];
        if ([nm isKindOfClass:[NSString class]]) sound = nm;
    }
    if (!title && !subtitle && !body) return KERN_FAILURE;

    NSData *archive = [self _archiveTitle:title subtitle:subtitle body:body sound:sound];
    if (!archive.length) return KERN_FAILURE;

    __block kern_return_t kr = KERN_FAILURE;
    dispatch_sync(_cacheQueue, ^{
        xpc_connection_t conn = [self _connForBundle:bundleID];
        if (!conn) return;
        xpc_object_t deliver = [self _newDeliver:archive];
        xpc_connection_send_message(conn, deliver);
        xpc_release(deliver);
        kr = KERN_SUCCESS;
    });
    return kr;
}

#pragma mark - Registration ops (no SpringBoard on macOS)

- (void)resetAppRegistrationForBundleID:(NSString *)bundleID
                             completion:(void (^)(SGControlError))completion {
    if (completion) completion([bundleID length] ? SGCERR_OK : SGCERR_INVALID_REQUEST);
}

// No native push subsystem on macOS, nothing to enumerate.
- (void)listNativePushAppsWithCompletion:(void (^)(SGControlError, NSData *))completion {
    if (completion) completion(SGCERR_UNSUPPORTED, nil);
}

- (void)registerInputAppPayload:(NSData *)payload
                     completion:(void (^)(SGControlError, NSString *))completion {
    (void)payload;
    if (completion) completion(SGCERR_UNSUPPORTED, @"input-app registration is iOS-only");
}

@end

#endif
