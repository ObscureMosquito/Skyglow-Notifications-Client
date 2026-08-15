#ifndef SKYGLOW_SG_PLATFORM_H
#define SKYGLOW_SG_PLATFORM_H

#import <Foundation/Foundation.h>
#import "capabilities/SGCapabilityTable.h"
#import "keychain/SGKeyStore.h"
#import "delivery/SGNotificationDelivery.h"
#import "network/SGNetworkInfo.h"
#import "system/SGSystemServices.h"

/** platform abstraction layer one host, so a singleton, my genius invention :) */
@interface SGPlatform : NSObject

+ (instancetype)currentPlatform;

- (BOOL)hasCapability:(SGCapability)capability;

@property (nonatomic, readonly) id<SGKeyStore>             keyStore;
@property (nonatomic, readonly) id<SGNotificationDelivery> delivery;
@property (nonatomic, readonly) id<SGNetworkInfo>          network;
@property (nonatomic, readonly) SGSystemServices          *system;

@end

#endif
