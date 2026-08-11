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
    SGCapabilityUnifiedLogging,
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

/** Version aware capability check */
- (BOOL)isCapabilityAvailable:(SGCapability)cap;

/** Marketing OS version */
@property (nonatomic, readonly) double systemVersion;

/** Convenience, equivalent to [self isCapabilityAvailable:SGCapabilityPersistentTimer]. */
@property (nonatomic, readonly) BOOL persistentTimerAvailable;

/** Convenience, equivalent to [self isCapabilityAvailable:SGCapabilityGrowthAlgorithm]. */
@property (nonatomic, readonly) BOOL growthAlgorithmAvailable;

/** Convenience, equivalent to [self isCapabilityAvailable:SGCapabilityPowerAssertion]. */
@property (nonatomic, readonly) BOOL powerAssertionAvailable;

/** Convenience, equivalent to [self isCapabilityAvailable:SGCapabilityScheduledWake]. */
@property (nonatomic, readonly) BOOL scheduledWakeAvailable;
@property (nonatomic, readonly) BOOL keepAliveOffloadAvailable;
@property (nonatomic, readonly) BOOL unifiedLoggingAvailable;

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

- (id)createGrowthAlgorithmWithInterval:(double)interval
                        minimumInterval:(double)minInterval
                        maximumInterval:(double)maxInterval;
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

/** Standalone, singleton-free check safe to call before [SGAvailability shared]. */
BOOL SGAvailability_HasUnifiedLogging(void);

#endif
