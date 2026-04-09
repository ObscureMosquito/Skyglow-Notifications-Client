#import "SGAvailability.h"
#import "SGKeepAliveStrategy.h"
#import <UIKit/UIKit.h>
#include <IOKit/pwr_mgt/IOPMLib.h>

/**
 * All private framework class names, version gating, and fallback logic
 * lives exclusively in this file.  The rest of the codebase interacts
 * only through the public SGAvailability API — no NSClassFromString,
 * dlopen, or version checks should exist anywhere else.
 */

#define SG_GROWTH_ACTION_SUCCESS 0
#define SG_GROWTH_ACTION_FAILURE 1

/**
 * Each row maps one SGCapability value to:
 *   - className:   the Objective-C class to probe via NSClassFromString,
 *                  or NULL for function-based APIs (always resolved)
 *   - minVersion:  lowest iOS version (inclusive) where the API is known-good
 *   - maxVersion:  highest iOS version (inclusive), or 0 for "no upper bound"
 *
 * To disable a capability: set maxVersion below minVersion (e.g. 0).
 * The builtin fallback (if one exists) will activate automatically.
 */
typedef struct {
    const char *className;
    double      minVersion;
    double      maxVersion;
} SGCapabilityEntry;

static const SGCapabilityEntry kCapabilityTable[SGCapabilityCount] = {
    [SGCapabilityPersistentTimer]  = { "PCPersistentTimer",           6.0, 0.0  },
    [SGCapabilityGrowthAlgorithm]  = { "PCMultiStageGrowthAlgorithm", 6.0, 6.99 },
    [SGCapabilityPowerAssertion]   = { NULL,                          2.0, 0.0  },
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

/**
 * SGBuiltinGrowthAlgorithm — thin ObjC wrapper around SGKeepAliveStrategy.
 *
 * Responds to the same selectors as PCMultiStageGrowthAlgorithm so that
 * callers (and the SGAvailability wrapper methods) work identically
 * regardless of which implementation is behind the `id`.
 */
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
    /* The C struct uses hardcoded min/max per network type.
       We reinitialize with the current interval clamped to new bounds. */
    (void)interval; /* bounds applied at reinit time */
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

/**
 * Reinitializes the underlying C algorithm for a network-type change.
 * Not part of the PCMultiStageGrowthAlgorithm interface — called
 * directly by SGAvailability's reinitialize method.
 */
- (void)reinitializeForWiFi:(BOOL)isWiFi savedInterval:(double)savedInterval {
    SGKeepAlive_Initialize(&_algo, isWiFi, savedInterval);
}

@end

@implementation SGAvailability {
    Class         _capabilityClasses[SGCapabilityCount];
    NSMutableSet *_activeAssertionIDs;
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
        _activeAssertionIDs = [[NSMutableSet alloc] init];
        _assertionLock      = [[NSLock alloc] init];

        /**
         * Walk the capability table, probing each class and gating on
         * the iOS version range where its selectors are known-good.
         * Entries with className == NULL are function-based APIs that
         * don't need class probing — only the version range matters.
         */
        double sysVer = [[[UIDevice currentDevice] systemVersion] doubleValue];

        for (NSInteger i = 0; i < SGCapabilityCount; i++) {
            SGCapabilityEntry e = kCapabilityTable[i];
            BOOL versionOK = (sysVer >= e.minVersion) &&
                             (e.maxVersion == 0.0 || sysVer <= e.maxVersion);

            if (!versionOK) {
                _capabilityClasses[i] = Nil;
                continue;
            }

            if (e.className) {
                _capabilityClasses[i] = NSClassFromString(@(e.className));
            } else {
                /* Function-based API — mark as available using a sentinel.
                   We use [NSNull class] so the slot is non-Nil. */
                _capabilityClasses[i] = [NSNull class];
            }
        }

        NSLog(@"[SGAvailability] iOS %.1f — "
              @"PCPersistentTimer: %@, "
              @"PCMultiStageGrowthAlgorithm: %@, "
              @"IOPMAssertion: %@",
              sysVer,
              [self isCapabilityAvailable:SGCapabilityPersistentTimer]  ? @"available" : @"unavailable",
              [self isCapabilityAvailable:SGCapabilityGrowthAlgorithm]  ? @"available" : @"unavailable",
              [self isCapabilityAvailable:SGCapabilityPowerAssertion]   ? @"available" : @"unavailable");
    }
    return self;
}

- (void)dealloc {
    [_activeAssertionIDs release];
    [_assertionLock release];
    [super dealloc];
}

#pragma mark - Capability Queries

- (BOOL)isCapabilityAvailable:(SGCapability)cap {
    if (cap < 0 || cap >= SGCapabilityCount) return NO;
    return _capabilityClasses[cap] != Nil;
}

- (BOOL)persistentTimerAvailable {
    return [self isCapabilityAvailable:SGCapabilityPersistentTimer];
}

- (BOOL)growthAlgorithmAvailable {
    return [self isCapabilityAvailable:SGCapabilityGrowthAlgorithm];
}

- (BOOL)powerAssertionAvailable {
    return [self isCapabilityAvailable:SGCapabilityPowerAssertion];
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
        NSLog(@"[SGAvailability] Growth algorithm: PCMultiStageGrowthAlgorithm — initial: %.0fs", interval);
    } else {
        algo = [[SGBuiltinGrowthAlgorithm alloc]
            initWithKeepAliveInterval:interval
                    loggingIdentifier:@"com.skyglow.sgn"
                        algorithmName:@"SkyglowKA"];
        NSLog(@"[SGAvailability] Growth algorithm: SGBuiltinGrowthAlgorithm — initial: %.0fs", interval);
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

    /* Builtin path — reinitialize in-place is cheaper, but we return
       a fresh object to keep the interface uniform (caller releases old). */
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

    /**
     * Track the assertion as active immediately so releasePowerAssertion: can
     * guard against double-release. Both the dispatch_after auto-timeout below
     * and the caller's explicit release funnel through releasePowerAssertion: —
     * whichever fires first removes the ID from the active set and releases the
     * OS assertion; the second call finds nothing in the set and is a no-op.
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
