#ifndef SKYGLOW_SG_SYSTEM_POWER_H
#define SKYGLOW_SG_SYSTEM_POWER_H

#import <Foundation/Foundation.h>

typedef void (^SGSystemPowerEventHandler)(void);

#define SG_POWER_ASSERTION_TIMEOUT_SEC 25

@protocol SGSystemPower <NSObject>

- (BOOL)startPowerEventMonitoringWithWakeHandler:(SGSystemPowerEventHandler)wakeHandler;
- (void)stopPowerEventMonitoring;
- (uint32_t)createTimedPowerAssertionWithName:(NSString *)name
                                      timeout:(NSTimeInterval)timeout;
- (void)releasePowerAssertion:(uint32_t)assertionID;
- (BOOL)scheduleWakeAfterInterval:(NSTimeInterval)seconds;
- (void)cancelPendingScheduledWake;

@end

#endif
