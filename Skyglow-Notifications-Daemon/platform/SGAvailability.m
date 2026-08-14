#import "SGAvailability.h"
#import "SGKeepAliveStrategy.h"
#import "SGLog.h"
#import "SGLogDiagnostics.h"
#include <TargetConditionals.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/IOMessage.h>

static double SGSystemVersionRead(void) {
    NSDictionary *sv = [NSDictionary dictionaryWithContentsOfFile:
        @"/System/Library/CoreServices/SystemVersion.plist"];
    NSString *ver = [sv objectForKey:@"ProductVersion"];
    return ver ? [ver doubleValue] : 0.0;   /* 0.0 = gate everything off */
}

extern IOReturn   IOPMSchedulePowerEvent(CFDateRef time_to_wake, CFStringRef my_id, CFStringRef type) __attribute__((weak_import));
extern IOReturn   IOPMCancelScheduledPowerEvent(CFDateRef time_to_wake, CFStringRef my_id, CFStringRef type) __attribute__((weak_import));
extern CFArrayRef IOPMCopyScheduledPowerEvents(void) __attribute__((weak_import));

#define SG_WAKE_EVENT_ID        CFSTR("com.skyglow.sgn")
#define SG_WAKE_EVENT_TYPE      CFSTR("wake")
#define SG_WAKE_MIN_INTERVAL_SEC 300.0

/**
 * All private framework class names, version gating, and fallback logic
 * lives exclusively in this file.
 */

#define SG_GROWTH_ACTION_SUCCESS 0
#define SG_GROWTH_ACTION_FAILURE 1

typedef enum {
    SGPlatformMaskIOS   = 1 << 0,
    SGPlatformMaskMacOS = 1 << 1,
} SGPlatformMask;

#if TARGET_OS_OSX
#define SG_CURRENT_PLATFORM_MASK SGPlatformMaskMacOS
#define SG_CURRENT_PLATFORM_NAME "macos"
#else
#define SG_CURRENT_PLATFORM_MASK SGPlatformMaskIOS
#define SG_CURRENT_PLATFORM_NAME "ios"
#endif

/**
 * Each row maps one SGCapability value to:
 *   - className:   the Objective-C class to probe via NSClassFromString,
 *                  or NULL for function-based APIs (always resolved)
 *   - platformMask: platforms on which the capability is meaningful
 *   - minVersion:  lowest iOS version (inclusive) where the API is known-good
 *   - maxVersion:  highest iOS version (inclusive), or 0 for "no upper bound"
 *
 * To disable a capability, set platformMask to 0. The builtin fallback (if
 * one exists) will activate automatically.
 */
typedef struct {
    const char *className;
    uint8_t     platformMask;
    double      minVersion;
    double      maxVersion;
} SGCapabilityEntry;

static const SGCapabilityEntry kCapabilityTable[SGCapabilityCount] = {
    [SGCapabilityPersistentTimer]  = { "PCPersistentTimer",           SGPlatformMaskIOS,                         6.0, 0.0  },
    [SGCapabilityGrowthAlgorithm]  = { "PCMultiStageGrowthAlgorithm", SGPlatformMaskIOS,                         6.0, 6.99 },
    [SGCapabilityPowerAssertion]   = { NULL,                          SGPlatformMaskIOS | SGPlatformMaskMacOS,    2.0, 0.0  },
    [SGCapabilityScheduledWake]    = { NULL,                          SGPlatformMaskIOS | SGPlatformMaskMacOS,    2.0, 5.99 },
    [SGCapabilityKeepAliveOffload] = { NULL,                          SGPlatformMaskIOS,                        99.0, 0.0  },  /* 99.0 = off until the offload path ships */
};

@interface NSObject (PCPrivateTimerAPI)
- (id)initWithTimeInterval:(NSTimeInterval)interval serviceIdentifier:(NSString *)sid target:(id)target selector:(SEL)sel userInfo:(id)userInfo;
- (void)setMinimumEarlyFireProportion:(double)proportion;
- (void)scheduleInRunLoop:(NSRunLoop *)runLoop;
@end

@interface NSObject (PCPrivateGrowthAlgorithmAPI)
- (id)initWithKeepAliveInterval:(double)interval loggingIdentifier:(NSString *)logId algorithmName:(NSString *)name;
- (void)setMinimumKeepAliveInterval:(double)interval;
- (void)setMaximumKeepAliveInterval:(double)interval;
- (double)currentKeepAliveInterval;
- (void)processNextAction:(int)action;
@end

/* SGBuiltinGrowthAlgorithm, thin ObjC wrapper around SGKeepAliveStrategy */
@interface SGBuiltinGrowthAlgorithm : NSObject {
    SGKeepAliveAlgorithm _algo;
}
- (id)initWithKeepAliveInterval:(double)interval loggingIdentifier:(NSString *)logId algorithmName:(NSString *)name;
- (void)setMinimumKeepAliveInterval:(double)interval;
- (void)setMaximumKeepAliveInterval:(double)interval;
- (double)currentKeepAliveInterval;
- (void)processNextAction:(int)action;
@end

@implementation SGBuiltinGrowthAlgorithm

- (id)initWithKeepAliveInterval:(double)interval
              loggingIdentifier:(NSString *)logId
                  algorithmName:(NSString *)name {
    if ((self = [super init])) {
        SGKeepAlive_Initialize(&_algo, true, interval);
    }
    return self;
}

- (void)setMinimumKeepAliveInterval:(double)interval {
    (void)interval;
}

- (void)setMaximumKeepAliveInterval:(double)interval {
    (void)interval;
}

- (double)currentKeepAliveInterval {
    return SGKeepAlive_GetCurrentInterval(&_algo);
}

- (void)processNextAction:(int)action {
    SGKeepAlive_ProcessHeartbeatResult(&_algo, (action == SG_GROWTH_ACTION_SUCCESS));
}

/* Reinitializes the underlying C algorithm for a network-type change */
- (void)reinitializeForWiFi:(BOOL)isWiFi savedInterval:(double)savedInterval {
    SGKeepAlive_Initialize(&_algo, isWiFi, savedInterval);
}

@end

@implementation SGAvailability {
    Class         _capabilityClasses[SGCapabilityCount];
    NSMutableSet *_activeAssertionIDs;
    NSLock       *_assertionLock;
    CFDateRef     _pendingWakeDate;
    NSLock       *_wakeLock;
    double        _systemVersion;
    io_connect_t  _powerRootPort;
    io_object_t   _powerNotifier;
    IONotificationPortRef _powerNotifyPort;
    SGSystemPowerEventHandler _wakeHandler;
    SGSystemPowerEventHandler _willSleepHandler;
    NSLock *_powerEventLock;
}

+ (SGAvailability *)shared {
    static SGAvailability *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
    });
    return instance;
}

- (id)init {
    if ((self = [super init])) {
        _activeAssertionIDs = [[NSMutableSet alloc] init];
        _assertionLock      = [[NSLock alloc] init];
        _wakeLock           = [[NSLock alloc] init];
        _pendingWakeDate    = NULL;
        _powerRootPort      = MACH_PORT_NULL;
        _powerNotifier      = MACH_PORT_NULL;
        _powerNotifyPort    = NULL;
        _powerEventLock     = [[NSLock alloc] init];

        _systemVersion = SGSystemVersionRead();
        double sysVer = _systemVersion;
        uint8_t platformMask = SG_CURRENT_PLATFORM_MASK;

        for (NSInteger i = 0; i < SGCapabilityCount; i++) {
            SGCapabilityEntry e = kCapabilityTable[i];
            BOOL platformOK = (e.platformMask & platformMask) != 0;
            BOOL versionOK = platformOK;
            if (platformMask == SGPlatformMaskIOS) {
                versionOK = versionOK && (sysVer >= e.minVersion) &&
                            (e.maxVersion == 0.0 || sysVer <= e.maxVersion);
            }

            if (!versionOK) {
                _capabilityClasses[i] = Nil;
                continue;
            }

            if (e.className) {
                _capabilityClasses[i] = NSClassFromString(@(e.className));
            } else {
                _capabilityClasses[i] = [NSNull class];
            }
        }

        if (_capabilityClasses[SGCapabilityScheduledWake] != Nil &&
            (IOPMSchedulePowerEvent == NULL || IOPMCancelScheduledPowerEvent == NULL)) {
            _capabilityClasses[SGCapabilityScheduledWake] = Nil;
        }

        SGLOGI(SGAvailability, "code=%s platform=%s version=%.1f persistent_timer=%s growth_algorithm=%s power_assertion=%s scheduled_wake=%s", SGND_AVAILABILITY_CAPABILITIES,
                    SG_CURRENT_PLATFORM_NAME, sysVer,
                    [self isCapabilityAvailable:SGCapabilityPersistentTimer] ? "available" : "unavailable",
                    [self isCapabilityAvailable:SGCapabilityGrowthAlgorithm] ? "available" : "unavailable",
                    [self isCapabilityAvailable:SGCapabilityPowerAssertion]  ? "available" : "unavailable",
                    [self isCapabilityAvailable:SGCapabilityScheduledWake]   ? "available" : "unavailable");
    }
    return self;
}

- (void)dealloc {
    [self stopPowerEventMonitoring];
    [self cancelPendingScheduledWake];
    [_activeAssertionIDs release];
    [_assertionLock release];
    [_wakeLock release];
    [_powerEventLock release];
    [super dealloc];
}

#pragma mark - System Power Events

static void SGPowerEventCallback(void *refcon, io_service_t service,
                                 natural_t messageType,
                                 void *messageArgument) {
    (void)service;
    SGAvailability *availability = (SGAvailability *)refcon;
    [availability->_powerEventLock lock];
    switch (messageType) {
        case kIOMessageSystemHasPoweredOn:
            if (availability->_wakeHandler) availability->_wakeHandler();
            break;
        case kIOMessageSystemWillSleep:
            if (availability->_willSleepHandler) {
                availability->_willSleepHandler();
            }
            IOAllowPowerChange(availability->_powerRootPort,
                               (long)messageArgument);
            break;
        case kIOMessageCanSystemSleep:
            IOAllowPowerChange(availability->_powerRootPort,
                               (long)messageArgument);
            break;
        default:
            break;
    }
    [availability->_powerEventLock unlock];
}

- (BOOL)startPowerEventMonitoringWithWakeHandler:
    (SGSystemPowerEventHandler)wakeHandler
    willSleepHandler:(SGSystemPowerEventHandler)willSleepHandler {
    [_powerEventLock lock];
    if (_powerRootPort != MACH_PORT_NULL) {
        [_powerEventLock unlock];
        return YES;
    }

    [_wakeHandler release];
    _wakeHandler = [wakeHandler copy];
    [_willSleepHandler release];
    _willSleepHandler = [willSleepHandler copy];

    _powerRootPort = IORegisterForSystemPower(self, &_powerNotifyPort,
                                               SGPowerEventCallback,
                                               &_powerNotifier);
    if (_powerRootPort == MACH_PORT_NULL) {
        [_wakeHandler release];
        _wakeHandler = nil;
        [_willSleepHandler release];
        _willSleepHandler = nil;
        SGLOGW(SGAvailability,
               "code=%s result=disabled reason=iokit_registration_failed",
               SGND_AVAILABILITY_POWER_NOTIFY_FAILED);
        [_powerEventLock unlock];
        return NO;
    }

    CFRunLoopAddSource(CFRunLoopGetMain(),
                       IONotificationPortGetRunLoopSource(_powerNotifyPort),
                       kCFRunLoopDefaultMode);
    SGLOGI(SGAvailability, "code=%s result=registered",
           SGND_AVAILABILITY_POWER_NOTIFY_READY);
    [_powerEventLock unlock];
    return YES;
}

- (void)stopPowerEventMonitoring {
    [_powerEventLock lock];
    if (_powerRootPort != MACH_PORT_NULL) {
        if (_powerNotifier != MACH_PORT_NULL) {
            IODeregisterForSystemPower(&_powerNotifier);
            _powerNotifier = MACH_PORT_NULL;
        }
        IOServiceClose(_powerRootPort);
        _powerRootPort = MACH_PORT_NULL;
        if (_powerNotifyPort) {
            CFRunLoopSourceRef source =
                IONotificationPortGetRunLoopSource(_powerNotifyPort);
            if (source) {
                CFRunLoopRemoveSource(CFRunLoopGetMain(), source,
                                      kCFRunLoopDefaultMode);
            }
            IONotificationPortDestroy(_powerNotifyPort);
            _powerNotifyPort = NULL;
        }
    }
    [_wakeHandler release];
    _wakeHandler = nil;
    [_willSleepHandler release];
    _willSleepHandler = nil;
    [_powerEventLock unlock];
}

#pragma mark - Capability Queries

- (BOOL)isCapabilityAvailable:(SGCapability)cap {
    if (cap < 0 || cap >= SGCapabilityCount) return NO;
    return _capabilityClasses[cap] != Nil;
}

- (BOOL)persistentTimerAvailable {
    return [self isCapabilityAvailable:SGCapabilityPersistentTimer];
}

- (BOOL)scheduledWakeAvailable {
    return [self isCapabilityAvailable:SGCapabilityScheduledWake];
}

- (BOOL)keepAliveOffloadAvailable {
    return [self isCapabilityAvailable:SGCapabilityKeepAliveOffload];
}

- (SGKeepAliveOffloadBackend)keepAliveOffloadBackend {
    if (![self keepAliveOffloadAvailable]) {
        return SGKeepAliveOffloadBackendNone;
    }
#if TARGET_OS_IPHONE
    if (_systemVersion >= 6.0 && _systemVersion < 7.0) {
        return SGKeepAliveOffloadBackendIOS6Broadcom;
    }
#endif
    return SGKeepAliveOffloadBackendNone;
}

#pragma mark - PCPersistentTimer

- (id)createPersistentTimerWithInterval:(double)interval
                      serviceIdentifier:(NSString *)sid
                                 target:(id)target
                               selector:(SEL)sel {
    Class cls = _capabilityClasses[SGCapabilityPersistentTimer];
    if (!cls) return nil;

    id timer = [[cls alloc]
        initWithTimeInterval:interval
           serviceIdentifier:sid
                      target:target
                    selector:sel
                    userInfo:nil];

    [timer setMinimumEarlyFireProportion:0.9];

    return timer;
}

- (void)schedulePersistentTimer:(id)timer inRunLoop:(NSRunLoop *)runLoop {
    if ([timer respondsToSelector:@selector(scheduleInRunLoop:)]) {
        [timer scheduleInRunLoop:runLoop];
    }
}

#pragma mark - Growth Algorithm

- (id)createGrowthAlgorithmWithInterval:(double)interval
                        minimumInterval:(double)minInterval
                        maximumInterval:(double)maxInterval {
    Class cls = _capabilityClasses[SGCapabilityGrowthAlgorithm];

    id algo;
    if (cls) {
        algo = [[cls alloc]
            initWithKeepAliveInterval:interval
                    loggingIdentifier:@"com.skyglow.sgn"
                        algorithmName:@"SkyglowKA"];
        SGLOGI(SGAvailability, "code=%s name=PCMultiStageGrowthAlgorithm initial=%.0fs", SGND_AVAILABILITY_GROWTH_ALGORITHM, interval);
    } else {
        algo = [[SGBuiltinGrowthAlgorithm alloc]
            initWithKeepAliveInterval:interval
                    loggingIdentifier:@"com.skyglow.sgn"
                        algorithmName:@"SkyglowKA"];
        SGLOGI(SGAvailability, "code=%s name=SGBuiltinGrowthAlgorithm initial=%.0fs", SGND_AVAILABILITY_GROWTH_ALGORITHM, interval);
    }

    [algo setMinimumKeepAliveInterval:minInterval];
    [algo setMaximumKeepAliveInterval:maxInterval];

    return algo;
}

- (double)currentIntervalForGrowthAlgorithm:(id)algo {
    if (!algo) return 0.0;
    return [algo currentKeepAliveInterval];
}

- (void)processResult:(BOOL)success forGrowthAlgorithm:(id)algo {
    if (!algo) return;
    [algo processNextAction:(success ? SG_GROWTH_ACTION_SUCCESS : SG_GROWTH_ACTION_FAILURE)];
}

- (id)reinitializeGrowthAlgorithmForWiFi:(BOOL)isWiFi
                           savedInterval:(double)savedInterval {
    double minKA = isWiFi ? 900.0 : 600.0;
    double maxKA = isWiFi ? 3600.0 : 1680.0;
    double initial = (savedInterval >= minKA && savedInterval <= maxKA) ? savedInterval : minKA;

    Class cls = _capabilityClasses[SGCapabilityGrowthAlgorithm];

    if (cls) {
        return [self createGrowthAlgorithmWithInterval:initial
                                       minimumInterval:minKA
                                       maximumInterval:maxKA];
    }

    SGBuiltinGrowthAlgorithm *algo = [[SGBuiltinGrowthAlgorithm alloc]
        initWithKeepAliveInterval:initial
                loggingIdentifier:@"com.skyglow.sgn"
                    algorithmName:@"SkyglowKA"];
    [algo reinitializeForWiFi:isWiFi savedInterval:savedInterval];

    return algo;
}

#pragma mark - Power Assertion Management

- (uint32_t)createTimedPowerAssertionWithName:(NSString *)name
                                      timeout:(NSTimeInterval)timeout {
    if (![self isCapabilityAvailable:SGCapabilityPowerAssertion]) return 0;

    IOPMAssertionID assertionID = 0;
    IOReturn ret = IOPMAssertionCreateWithName(
        kIOPMAssertionTypePreventUserIdleSystemSleep,
        kIOPMAssertionLevelOn,
        (CFStringRef)name,
        &assertionID);

    if (ret != kIOReturnSuccess) return 0;

    uint32_t capturedID = (uint32_t)assertionID;
    [_assertionLock lock];
    [_activeAssertionIDs addObject:@(capturedID)];
    [_assertionLock unlock];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC)),
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self releasePowerAssertion:capturedID];
    });

    return capturedID;
}

- (void)releasePowerAssertion:(uint32_t)assertionID {
    if (assertionID == 0) return;

    NSNumber *key = @(assertionID);
    [_assertionLock lock];
    BOOL wasActive = [_activeAssertionIDs containsObject:key];
    if (wasActive) {
        [_activeAssertionIDs removeObject:key];
    }
    [_assertionLock unlock];

    if (wasActive) {
        IOPMAssertionRelease((IOPMAssertionID)assertionID);
    }
}

#pragma mark - Scheduled Wake

- (BOOL)scheduleWakeAfterInterval:(NSTimeInterval)seconds {
    if (![self isCapabilityAvailable:SGCapabilityScheduledWake]) return NO;
    if (seconds < SG_WAKE_MIN_INTERVAL_SEC) seconds = SG_WAKE_MIN_INTERVAL_SEC;

    [_wakeLock lock];
    if (_pendingWakeDate) {
        IOPMCancelScheduledPowerEvent(_pendingWakeDate, SG_WAKE_EVENT_ID, SG_WAKE_EVENT_TYPE);
        CFRelease(_pendingWakeDate);
        _pendingWakeDate = NULL;
    }

    CFDateRef when = CFDateCreate(NULL, CFAbsoluteTimeGetCurrent() + seconds);
    if (!when) {
        [_wakeLock unlock];
        return NO;
    }

    IOReturn r = IOPMSchedulePowerEvent(when, SG_WAKE_EVENT_ID, SG_WAKE_EVENT_TYPE);
    if (r != kIOReturnSuccess) {
        CFRelease(when);
        [_wakeLock unlock];
        SGLOGW(SGAvailability, "code=%s seconds=%.0f ioreturn=0x%08x result=rejected",
               SGND_SCHEDULED_WAKE_FAILED, seconds, r);
        return NO;
    }
    _pendingWakeDate = when;
    [_wakeLock unlock];

    SGLOGI(SGAvailability, "code=%s seconds=%.0f result=armed", SGND_SCHEDULED_WAKE_ARMED, seconds);
    return YES;
}

- (void)cancelPendingScheduledWake {
    [_wakeLock lock];
    if (!_pendingWakeDate) {
        [_wakeLock unlock];
        return;
    }
    if (IOPMCancelScheduledPowerEvent) {
        IOPMCancelScheduledPowerEvent(_pendingWakeDate, SG_WAKE_EVENT_ID, SG_WAKE_EVENT_TYPE);
    }
    CFRelease(_pendingWakeDate);
    _pendingWakeDate = NULL;
    [_wakeLock unlock];
    SGLOGI(SGAvailability, "code=%s result=cancelled", SGND_SCHEDULED_WAKE_CANCELLED);
}

@end

