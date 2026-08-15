#import "capabilities/SGCapabilityTable.h"
#import "SGLog.h"
#import "SGLogDiagnostics.h"
#include <IOKit/pwr_mgt/IOPMLib.h>

extern IOReturn IOPMSchedulePowerEvent(CFDateRef time_to_wake, CFStringRef my_id, CFStringRef type) __attribute__((weak_import));
extern IOReturn IOPMCancelScheduledPowerEvent(CFDateRef time_to_wake, CFStringRef my_id, CFStringRef type) __attribute__((weak_import));

@implementation SGCapabilityTable {
    BOOL _available[SGCapabilityCount];
}

- (id)init {
    if ((self = [super init])) {
        _available[SGCapabilityPowerAssertion] = YES;
        _available[SGCapabilityScheduledWake]  = IOPMSchedulePowerEvent != NULL &&
                                                 IOPMCancelScheduledPowerEvent != NULL;

        SGLOGI(SGCapabilityTable, "code=%s platform=macos cf_version=%.2f power_assertion=%d scheduled_wake=%d",
               SGND_AVAILABILITY_CAPABILITIES, kCFCoreFoundationVersionNumber,
               _available[SGCapabilityPowerAssertion], _available[SGCapabilityScheduledWake]);
    }
    return self;
}

- (BOOL)hasCapability:(SGCapability)capability {
    return capability >= 0 && capability < SGCapabilityCount && _available[capability];
}

@end
