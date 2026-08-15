#ifndef SKYGLOW_SG_CAPABILITY_TABLE_H
#define SKYGLOW_SG_CAPABILITY_TABLE_H

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, SGCapability) {
    SGCapabilityPowerAssertion,
    SGCapabilityScheduledWake,
    SGCapabilityKeepAliveOffload,
    SGCapabilityCellular,
    SGCapabilityCount           /** must be last */
};

/** Answers hasCapability, each platform supplies its own implementation. */
@interface SGCapabilityTable : NSObject
- (BOOL)hasCapability:(SGCapability)capability;
@end

#endif
