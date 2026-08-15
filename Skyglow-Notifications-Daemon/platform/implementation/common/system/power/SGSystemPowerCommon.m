#import "SGSystemPowerCommon.h"
#import "SGLog.h"
#import "SGLogDiagnostics.h"
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/IOMessage.h>

extern IOReturn IOPMSchedulePowerEvent(CFDateRef time_to_wake, CFStringRef my_id, CFStringRef type) __attribute__((weak_import));
extern IOReturn IOPMCancelScheduledPowerEvent(CFDateRef time_to_wake, CFStringRef my_id, CFStringRef type) __attribute__((weak_import));

#define SG_WAKE_EVENT_ID         CFSTR("com.skyglow.sgn")
#define SG_WAKE_EVENT_TYPE       CFSTR("wake")
#define SG_WAKE_MIN_INTERVAL_SEC 300.0

@implementation SGSystemPowerCommon {
    NSMutableSet *_activeAssertionIDs;
    NSLock       *_assertionLock;
    CFDateRef     _pendingWakeDate;
    NSLock       *_wakeLock;
    io_connect_t  _powerRootPort;
    io_object_t   _powerNotifier;
    IONotificationPortRef _powerNotifyPort;
    SGSystemPowerEventHandler _wakeHandler;
    NSLock *_powerEventLock;
}

- (id)init {
    if ((self = [super init])) {
        _activeAssertionIDs = [[NSMutableSet alloc] init];
        _assertionLock      = [[NSLock alloc] init];
        _wakeLock           = [[NSLock alloc] init];
        _powerEventLock     = [[NSLock alloc] init];
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
    SGSystemPowerCommon *power = (SGSystemPowerCommon *)refcon;
    [power->_powerEventLock lock];
    switch (messageType) {
        case kIOMessageSystemHasPoweredOn:
            if (power->_wakeHandler) power->_wakeHandler();
            break;
        case kIOMessageSystemWillSleep:
        case kIOMessageCanSystemSleep:
            IOAllowPowerChange(power->_powerRootPort,
                               (long)messageArgument);
            break;
        default:
            break;
    }
    [power->_powerEventLock unlock];
}

- (BOOL)startPowerEventMonitoringWithWakeHandler:(SGSystemPowerEventHandler)wakeHandler {
    [_powerEventLock lock];
    if (_powerRootPort != MACH_PORT_NULL) {
        [_powerEventLock unlock];
        return YES;
    }

    [_wakeHandler release];
    _wakeHandler = [wakeHandler copy];

    _powerRootPort = IORegisterForSystemPower(self, &_powerNotifyPort,
                                               SGPowerEventCallback,
                                               &_powerNotifier);
    if (_powerRootPort == MACH_PORT_NULL) {
        [_wakeHandler release];
        _wakeHandler = nil;
        SGLOGW(SGSystemPower,
               "code=%s result=disabled reason=iokit_registration_failed",
               SGND_AVAILABILITY_POWER_NOTIFY_FAILED);
        [_powerEventLock unlock];
        return NO;
    }

    CFRunLoopAddSource(CFRunLoopGetMain(),
                       IONotificationPortGetRunLoopSource(_powerNotifyPort),
                       kCFRunLoopDefaultMode);
    SGLOGI(SGSystemPower, "code=%s result=registered",
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
    [_powerEventLock unlock];
}

#pragma mark - Power Assertion Management

- (uint32_t)createTimedPowerAssertionWithName:(NSString *)name
                                      timeout:(NSTimeInterval)timeout {
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
    if (IOPMSchedulePowerEvent == NULL) return NO;
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
        SGLOGW(SGSystemPower, "code=%s seconds=%.0f ioreturn=0x%08x result=rejected",
               SGND_SCHEDULED_WAKE_FAILED, seconds, r);
        return NO;
    }
    _pendingWakeDate = when;
    [_wakeLock unlock];

    SGLOGI(SGSystemPower, "code=%s seconds=%.0f result=armed", SGND_SCHEDULED_WAKE_ARMED, seconds);
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
    SGLOGI(SGSystemPower, "code=%s result=cancelled", SGND_SCHEDULED_WAKE_CANCELLED);
}

@end
