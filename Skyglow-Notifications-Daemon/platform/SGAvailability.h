#ifndef SKYGLOW_SG_AVAILABILITY_H
#define SKYGLOW_SG_AVAILABILITY_H

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, SGCapability) {
    SGCapabilityPersistentTimer,
    SGCapabilityGrowthAlgorithm,
    SGCapabilityPowerAssertion,
    SGCapabilityScheduledWake,
    SGCapabilityKeepAliveOffload,
    SGCapabilityCount  /* sentinel — must be last */
};

/* Version-specific implementation selected centrally for NIC keepalive. */
typedef NS_ENUM(NSInteger, SGKeepAliveOffloadBackend) {
    SGKeepAliveOffloadBackendNone = 0,
    SGKeepAliveOffloadBackendIOS6Broadcom,
};

/* Centralised runtime capability detection and factory. */
@interface SGAvailability : NSObject

+ (SGAvailability *)shared;

/** Version-aware capability check, the single source of truth. */
- (BOOL)isCapabilityAvailable:(SGCapability)cap;

/* Marketing OS version as a double */
@property (nonatomic, readonly) double systemVersion;

/* Convenience, equivalent to [self isCapabilityAvailable:SGCapabilityPersistentTimer]. */
@property (nonatomic, readonly) BOOL persistentTimerAvailable;

/* Convenience, equivalent to [self isCapabilityAvailable:SGCapabilityGrowthAlgorithm]. */
@property (nonatomic, readonly) BOOL growthAlgorithmAvailable;

/* Convenience, equivalent to [self isCapabilityAvailable:SGCapabilityPowerAssertion]. */
@property (nonatomic, readonly) BOOL powerAssertionAvailable;

@property (nonatomic, readonly) BOOL scheduledWakeAvailable;

@property (nonatomic, readonly) BOOL keepAliveOffloadAvailable;

/* Selected version-specific offload implementation, or None. */
@property (nonatomic, readonly) SGKeepAliveOffloadBackend keepAliveOffloadBackend;

#pragma mark - PCPersistentTimer

/* Creates and returns a PCPersistentTimer configured for keepalive use */
- (id)createPersistentTimerWithInterval:(double)interval
                      serviceIdentifier:(NSString *)sid
                                 target:(id)target
                               selector:(SEL)sel;

/* Schedules a persistent timer in the given run loop */
- (void)schedulePersistentTimer:(id)timer inRunLoop:(NSRunLoop *)runLoop;

#pragma mark - Growth Algorithm

/* Creates and returns a growth algorithm — always non-nil */
- (id)createGrowthAlgorithmWithInterval:(double)interval
                        minimumInterval:(double)minInterval
                        maximumInterval:(double)maxInterval;

/* Returns the current interval from a growth algorithm instance */
- (double)currentIntervalForGrowthAlgorithm:(id)algo;

/* Feeds a success/failure result into a growth algorithm instance */
- (void)processResult:(BOOL)success forGrowthAlgorithm:(id)algo;

/* Reinitialises a growth algorithm for a network-type change */
- (id)reinitializeGrowthAlgorithmForWiFi:(BOOL)isWiFi
                           savedInterval:(double)savedInterval;

#pragma mark - Power Assertion Management

/* Shared backstop for every power assertion we hold across the receive path */
#define SG_POWER_ASSERTION_TIMEOUT_SEC 25

/**
 * Creates a time-limited power assertion to prevent system sleep
 * during notification processing. 
 */
- (uint32_t)createTimedPowerAssertionWithName:(NSString *)name
                                      timeout:(NSTimeInterval)timeout;

/**
 * Releases a power assertion previously created by
 * createTimedPowerAssertionWithName:timeout:.
 */
- (void)releasePowerAssertion:(uint32_t)assertionID;

#pragma mark - Scheduled Wake (pre-iOS-6 keepalive fallback)

/**
 * Schedules a hardware RTC wake `seconds` from now (clamped to a sane floor)
 * via IOPMSchedulePowerEvent, replacing any previously-scheduled wake. 
 */
- (BOOL)scheduleWakeAfterInterval:(NSTimeInterval)seconds;

/**
 * Cancels any wake previously armed by scheduleWakeAfterInterval:.  Safe to
 * call when nothing is scheduled.
 */
- (void)cancelPendingScheduledWake;

@end

#endif
