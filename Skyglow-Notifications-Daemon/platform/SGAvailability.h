#ifndef SKYGLOW_SG_AVAILABILITY_H
#define SKYGLOW_SG_AVAILABILITY_H

#import <Foundation/Foundation.h>

typedef void (^SGSystemPowerEventHandler)(void);

typedef NS_ENUM(NSInteger, SGCapability) {
    SGCapabilityPersistentTimer,
    SGCapabilityGrowthAlgorithm,
    SGCapabilityPowerAssertion,
    SGCapabilityScheduledWake,
    SGCapabilityKeepAliveOffload,
    SGCapabilityCount  /** must be last */
};

/** Version specific implementation selected centrally for NIC keepalive. */
typedef NS_ENUM(NSInteger, SGKeepAliveOffloadBackend) {
    SGKeepAliveOffloadBackendNone = 0,
    SGKeepAliveOffloadBackendIOS6Broadcom,
};

/** Centralised runtime capability detection and factory. */
@interface SGAvailability : NSObject

+ (SGAvailability *)shared;

@property (nonatomic, readonly) BOOL persistentTimerAvailable;
@property (nonatomic, readonly) BOOL scheduledWakeAvailable;

/* Selected version-specific offload implementation, or None. */
@property (nonatomic, readonly) SGKeepAliveOffloadBackend keepAliveOffloadBackend;

#pragma mark - System Power Events

- (BOOL)startPowerEventMonitoringWithWakeHandler:
    (SGSystemPowerEventHandler)wakeHandler
    willSleepHandler:(SGSystemPowerEventHandler)willSleepHandler;
- (void)stopPowerEventMonitoring;

#pragma mark - PCPersistentTimer

- (id)createPersistentTimerWithInterval:(double)interval
                      serviceIdentifier:(NSString *)sid
                                 target:(id)target
                               selector:(SEL)sel;
- (void)schedulePersistentTimer:(id)timer inRunLoop:(NSRunLoop *)runLoop;

#pragma mark - Growth Algorithm

- (double)currentIntervalForGrowthAlgorithm:(id)algo;
- (void)processResult:(BOOL)success forGrowthAlgorithm:(id)algo;
- (id)reinitializeGrowthAlgorithmForWiFi:(BOOL)isWiFi
                           savedInterval:(double)savedInterval;

#pragma mark - Power Assertion Management

#define SG_POWER_ASSERTION_TIMEOUT_SEC 25

- (uint32_t)createTimedPowerAssertionWithName:(NSString *)name
                                      timeout:(NSTimeInterval)timeout;
- (void)releasePowerAssertion:(uint32_t)assertionID;
- (BOOL)scheduleWakeAfterInterval:(NSTimeInterval)seconds;
- (void)cancelPendingScheduledWake;

@end

#endif
