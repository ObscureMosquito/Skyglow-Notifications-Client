#ifndef SKYGLOW_SG_CONTROL_CHANNEL_H
#define SKYGLOW_SG_CONTROL_CHANNEL_H

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import "SGControlChannelProtocol.h"

@class SGControlChannel;

/** Handler must call exactly one of reply or replyError before returning. */
typedef void (^SGControlReplyBlock)(SGControlMessageType type, NSData *payloadOrNil);
typedef void (^SGControlReplyErrorBlock)(SGControlError error, NSString *detailOrNil);
typedef void (^SGControlMessageHandler)(const SGControlChannelMessage *request,
                                         SGControlReplyBlock reply,
                                         SGControlReplyErrorBlock replyError);

typedef void (^SGControlClientCompletion)(SGControlError error,
                                           const SGControlChannelMessage *responseOrNull);

/** Fires on the global concurrent queue. */
typedef void (^SGControlEventHandler)(SGControlEventType eventType, NSData *dataOrNil);

typedef void (^SGControlSubscribeCompletion)(SGControlError error, uint64_t subscriptionId);

typedef void (^SGControlConnectionHandler)(BOOL connected);

@interface SGControlChannel : NSObject

/** Inert until -start is called. */
+ (instancetype)serverWithServiceName:(const char *)serviceName;

/** Inert until -start is called. */
+ (instancetype)clientForServiceName:(const char *)serviceName;

- (BOOL)start;

/** Idempotent. Cancels pending requests with SGCERR_UNREACHABLE. */
- (void)stop;

- (void)registerHandler:(SGControlMessageHandler)handler
         forMessageType:(SGControlMessageType)messageType;

- (void)postEvent:(SGControlEventType)eventType
          payload:(NSData *)payloadOrNil;

/** Queues requests while disconnected; replays on reconnect. */
- (void)sendRequest:(SGControlMessageType)messageType
            payload:(NSData *)payloadOrNil
            timeout:(NSTimeInterval)timeout
         completion:(SGControlClientCompletion)completion;

- (void)subscribeToEvent:(SGControlEventType)eventType
                 handler:(SGControlEventHandler)handler
              completion:(SGControlSubscribeCompletion)completion;

- (void)unsubscribe:(uint64_t)subscriptionId;

- (void)setConnectionHandler:(SGControlConnectionHandler)handler;

- (BOOL)isConnected;

@end

#endif
