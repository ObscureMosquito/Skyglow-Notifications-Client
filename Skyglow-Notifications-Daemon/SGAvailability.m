#import "SGAvailability.h"
#include <IOKit/pwr_mgt/IOPMLib.h>

/**
 * All private framework class names and probing logic lives exclusively
 * in this file. The rest of the codebase interacts only through the
 * public SGAvailability API — no NSClassFromString, dlopen, or version
 * checks should exist anywhere else.
 */

#define SG_GROWTH_ACTION_SUCCESS 0
#define SG_GROWTH_ACTION_FAILURE 1

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

@implementation SGAvailability {
    Class         _persistentTimerClass;
    Class         _growthAlgorithmClass;
    NSMutableSet *_activeAssertionIDs;   // IDs created but not yet released
    NSLock       *_assertionLock;
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
        /**
         * Probe for PersistentConnection.framework classes.
         * NSClassFromString returns nil if the class doesn't exist (iOS 5),
         * non-nil if the framework is loaded (iOS 6+).
         *
         * We do NOT dlopen — the framework must be linked at build time
         * for the iOS 6 target. On iOS 5 builds where it's not linked,
         * these simply return nil.
         */
        _persistentTimerClass  = NSClassFromString(@"PCPersistentTimer");
        _growthAlgorithmClass  = NSClassFromString(@"PCMultiStageGrowthAlgorithm");
        _activeAssertionIDs    = [[NSMutableSet alloc] init];
        _assertionLock         = [[NSLock alloc] init];

        NSLog(@"[SGAvailability] PCPersistentTimer: %@, PCMultiStageGrowthAlgorithm: %@",
              _persistentTimerClass  ? @"available" : @"unavailable",
              _growthAlgorithmClass  ? @"available" : @"unavailable");
    }
    return self;
}

- (void)dealloc {
    [_activeAssertionIDs release];
    [_assertionLock release];
    [super dealloc];
}

#pragma mark - Capability Queries

- (BOOL)persistentTimerAvailable {
    return _persistentTimerClass != Nil;
}

- (BOOL)growthAlgorithmAvailable {
    return _growthAlgorithmClass != Nil;
}

#pragma mark - PCPersistentTimer Factory

- (id)createPersistentTimerWithInterval:(double)interval
                      serviceIdentifier:(NSString *)sid
                                 target:(id)target
                               selector:(SEL)sel {
    if (!_persistentTimerClass) return nil;

    id timer = [[_persistentTimerClass alloc]
        initWithTimeInterval:interval
           serviceIdentifier:sid
                      target:target
                    selector:sel
                    userInfo:nil];

    /**
     * Allow the timer to fire up to 10% early if the system is already
     * awake for another reason (coalesces with other maintenance wakes).
     */
    [timer setMinimumEarlyFireProportion:0.9];

    return timer;
}

- (void)schedulePersistentTimer:(id)timer inRunLoop:(NSRunLoop *)runLoop {
    if ([timer respondsToSelector:@selector(scheduleInRunLoop:)]) {
        [timer scheduleInRunLoop:runLoop];
    }
}

#pragma mark - PCMultiStageGrowthAlgorithm Factory

- (id)createGrowthAlgorithmWithInterval:(double)interval
                    minimumInterval:(double)minInterval
                    maximumInterval:(double)maxInterval {
    if (!_growthAlgorithmClass) return nil;

    id algo = [[_growthAlgorithmClass alloc]
        initWithKeepAliveInterval:interval
                loggingIdentifier:@"com.skyglow.sgn"
                    algorithmName:@"SkyglowKA"];
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

- (void)setMinimumInterval:(double)min maximumInterval:(double)max
       forGrowthAlgorithm:(id)algo {
    if (!algo) return;
    [algo setMinimumKeepAliveInterval:min];
    [algo setMaximumKeepAliveInterval:max];
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

    /**
     * Track the assertion as active immediately so releasePowerAssertion: can
     * guard against double-release. Both the dispatch_after auto-timeout below
     * and the caller's explicit release funnel through releasePowerAssertion: —
     * whichever fires first removes the ID from the active set and releases the
     * OS assertion; the second call finds nothing in the set and is a no-op.
     *
     * Tracking active (not released) IDs means the set is bounded by the number
     * of concurrent assertions (typically 0-1) rather than growing indefinitely.
     *
     * Previously used `__block _Atomic IOPMAssertionID` which is undefined
     * behavior in C11: `__block` moves the variable to the heap, where `_Atomic`
     * has no specified semantics and the CAS may not be atomic on ARM.
     */
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

    /**
     * Atomically remove the ID from the active set. If it was there, this is the
     * first release — perform it. If it was already removed by a prior call, skip.
     * This prevents double-release regardless of whether the timeout path or the
     * explicit caller path fires first.
     */
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

@end