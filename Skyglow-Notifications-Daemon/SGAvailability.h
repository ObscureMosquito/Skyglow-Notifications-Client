#ifndef SKYGLOW_SG_AVAILABILITY_H
#define SKYGLOW_SG_AVAILABILITY_H

#import <Foundation/Foundation.h>

/**
 * Each entry represents one system capability (private or public) that
 * is gated by iOS version in SGAvailability.m.
 *
 * To add a new capability:
 *   1. Add an entry here (before SGCapabilityCount).
 *   2. Add one line to kCapabilityTable in SGAvailability.m.
 *   3. Add factory/wrapper methods in SGAvailability if needed.
 *
 * To disable a capability: set its maxVersion in the table to 0
 *   (effectively below any minVersion).  The builtin fallback — if one
 *   exists — will activate automatically.
 */
typedef NS_ENUM(NSInteger, SGCapability) {
    SGCapabilityPersistentTimer,
    SGCapabilityGrowthAlgorithm,
    SGCapabilityPowerAssertion,
    SGCapabilityScheduledWake,
    SGCapabilityKeepAliveOffload,
    SGCapabilityCount  /* sentinel — must be last */
};

/**
 * SGAvailability — Centralised runtime capability detection and factory.
 *
 * Every private (and select public) API the daemon uses is probed once
 * at startup, gated by iOS version, and exposed through factory methods
 * that return a working implementation — either the system class or a
 * builtin fallback.  Callers never branch on availability; they just
 * request an object and use it.
 *
 * No NSClassFromString, dlopen, or version checks should appear
 * anywhere outside this class.
 *
 * Usage:
 *   id algo = [[SGAvailability shared]
 *       createGrowthAlgorithmWithInterval:600 minimumInterval:600 maximumInterval:1680];
 *   // Always non-nil — private API or builtin fallback.
 */
@interface SGAvailability : NSObject

+ (SGAvailability *)shared;

/** Version-aware capability check, the single source of truth. */
- (BOOL)isCapabilityAvailable:(SGCapability)cap;

/** Convenience, equivalent to [self isCapabilityAvailable:SGCapabilityPersistentTimer]. */
@property (nonatomic, readonly) BOOL persistentTimerAvailable;

/** Convenience, equivalent to [self isCapabilityAvailable:SGCapabilityGrowthAlgorithm]. */
@property (nonatomic, readonly) BOOL growthAlgorithmAvailable;

/** Convenience, equivalent to [self isCapabilityAvailable:SGCapabilityPowerAssertion]. */
@property (nonatomic, readonly) BOOL powerAssertionAvailable;

@property (nonatomic, readonly) BOOL scheduledWakeAvailable;

@property (nonatomic, readonly) BOOL keepAliveOffloadAvailable;

#pragma mark - PCPersistentTimer

/**
 * Creates and returns a PCPersistentTimer configured for keepalive use.
 * Returns nil if the capability is unavailable (no builtin fallback).
 * Caller owns the returned object (retain count +1).
 */
- (id)createPersistentTimerWithInterval:(double)interval
                      serviceIdentifier:(NSString *)sid
                                 target:(id)target
                               selector:(SEL)sel;

/**
 * Schedules a persistent timer in the given run loop.
 */
- (void)schedulePersistentTimer:(id)timer inRunLoop:(NSRunLoop *)runLoop;

#pragma mark - Growth Algorithm

/**
 * Creates and returns a growth algorithm — always non-nil.
 *
 * Returns the system PCMultiStageGrowthAlgorithm when the capability
 * is available, otherwise a builtin implementation backed by
 * SGKeepAliveStrategy.  The returned object responds to the same
 * selectors in both cases; use the wrapper methods below to interact.
 *
 * Caller owns the returned object (retain count +1).
 */
- (id)createGrowthAlgorithmWithInterval:(double)interval
                        minimumInterval:(double)minInterval
                        maximumInterval:(double)maxInterval;

/**
 * Returns the current interval from a growth algorithm instance.
 * Safe to call with any object — returns 0.0 if algo is nil.
 */
- (double)currentIntervalForGrowthAlgorithm:(id)algo;

/**
 * Feeds a success/failure result into a growth algorithm instance.
 */
- (void)processResult:(BOOL)success forGrowthAlgorithm:(id)algo;

/**
 * Reinitialises a growth algorithm for a network-type change.
 * Releases the old instance and returns a new one.
 * Caller owns the returned object (retain count +1).
 */
- (id)reinitializeGrowthAlgorithmForWiFi:(BOOL)isWiFi
                           savedInterval:(double)savedInterval;

#pragma mark - Power Assertion Management

/**
 * Creates a time-limited power assertion to prevent system sleep
 * during notification processing. Returns an opaque assertion ID
 * that must be released with releasePowerAssertion:.
 * A dispatch_after auto-releases after timeout seconds as a safety net.
 * Returns 0 on failure or if the capability is unavailable.
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
 * via IOPMSchedulePowerEvent, replacing any previously-scheduled wake.  Used
 * only pre-iOS-6 (iOS 6+ uses PCPersistentTimer) to send a keepalive ping
 * during uninterrupted deep sleep.  Returns YES if the OS accepted the
 * schedule request.  No-op returning NO when the capability does not apply.
 */
- (BOOL)scheduleWakeAfterInterval:(NSTimeInterval)seconds;

/**
 * Cancels any wake previously armed by scheduleWakeAfterInterval:.  Safe to
 * call when nothing is scheduled.
 */
- (void)cancelPendingScheduledWake;

@end

#endif
