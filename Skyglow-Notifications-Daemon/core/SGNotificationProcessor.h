#ifndef SKYGLOW_SG_NOTIFICATION_PROCESSOR_H
#define SKYGLOW_SG_NOTIFICATION_PROCESSOR_H

#import <Foundation/Foundation.h>
#import "SGControlChannelProtocol.h"

typedef SGControlError (^SGNotificationDeliveryHandler)(NSString *bundleID,
                                                         NSDictionary *payload);

@interface SGNotificationProcessor : NSObject

- (instancetype)initWithDeliveryHandler:(SGNotificationDeliveryHandler)handler;
- (void)processNotification:(NSDictionary *)message;
- (void)kickPendingDeliveryDrain;
- (void)suspendPendingDeliveryRetries;
- (void)resetInMemoryDeduplication;

@end

#endif
