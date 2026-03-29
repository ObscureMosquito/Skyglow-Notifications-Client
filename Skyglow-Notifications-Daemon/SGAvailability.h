#ifndef SKYGLOW_SG_AVAILABILITY_H
#define SKYGLOW_SG_AVAILABILITY_H

#import <Foundation/Foundation.h>

/**
 * SGAvailability — Runtime capability detection singleton.
 *
 * Probes once at startup for private framework availability, then
 * provides simple boolean queries and factory methods for the rest
 * of the codebase. No NSClassFromString, dlopen, or version checks
 * should appear anywhere outside this class.
 *
 * Usage:
 *   if ([SGAvailability shared].persistentTimerAvailable) {
 *       id timer = [[SGAvailability shared] createPersistentTimerWithInterval:...];
 *   }
 */
@interface SGAvailability : NSObject

+ (SGAvailability *)shared;

/** YES if PersistentConnection.framework is loaded and usable (iOS 6+). */
@property (nonatomic, readonly) BOOL persistentTimerAvailable;

/** YES if PCMultiStageGrowthAlgorithm is available (iOS 6+). */
@property (nonatomic, readonly) BOOL growthAlgorithmAvailable;

#pragma mark - PCPersistentTimer Factory

/**
 * Creates and returns a PCPersistentTimer configured for keepalive use.
 * Returns nil if persistentTimerAvailable is NO.
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

#pragma mark - PCMultiStageGrowthAlgorithm Factory

/**
 * Creates and returns a PCMultiStageGrowthAlgorithm configured for keepalive use.
 * Returns nil if growthAlgorithmAvailable is NO.
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
 * action: 0 = success, 1 = failure.
 */
- (void)processResult:(BOOL)success forGrowthAlgorithm:(id)algo;

/**
 * Sets min/max on an existing growth algorithm instance.
 */
- (void)setMinimumInterval:(double)min maximumInterval:(double)max
       forGrowthAlgorithm:(id)algo;

#pragma mark - Power Assertion Management

/**
 * Creates a time-limited power assertion to prevent system sleep
 * during notification processing. Returns an opaque assertion ID
 * that must be released with releasePowerAssertion:.
 * A dispatch_after auto-releases after timeout seconds as a safety net.
 * Returns 0 on failure.
 */
- (uint32_t)createTimedPowerAssertionWithName:(NSString *)name
                                      timeout:(NSTimeInterval)timeout;

/**
 * Releases a power assertion previously created by
 * createTimedPowerAssertionWithName:timeout:.
 */
- (void)releasePowerAssertion:(uint32_t)assertionID;

@end

#endif