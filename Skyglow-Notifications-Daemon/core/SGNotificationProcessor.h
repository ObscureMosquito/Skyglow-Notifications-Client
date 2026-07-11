#ifndef SKYGLOW_SG_NOTIFICATION_PROCESSOR_H
#define SKYGLOW_SG_NOTIFICATION_PROCESSOR_H

#import <Foundation/Foundation.h>
#import <mach/mach.h>

typedef kern_return_t (^SGNotificationDeliveryHandler)(NSString *bundleID,
                                                        NSDictionary *payload);

/**
 * Owns notification disposition after a wire frame has been decoded: durable
 * deduplication, decrypt/decompress/parse, local delivery, ACK selection, and
 * the persistent local-redelivery queue.
 */
@interface SGNotificationProcessor : NSObject

- (instancetype)initWithDeliveryHandler:(SGNotificationDeliveryHandler)handler;
- (void)processNotification:(NSDictionary *)message;
- (void)kickPendingDeliveryDrain;
- (void)suspendPendingDeliveryRetries;
- (void)resetInMemoryDeduplication;

@end

#endif
