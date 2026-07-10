#ifndef SKYGLOW_SG_CONTROL_CHANNEL_H
#define SKYGLOW_SG_CONTROL_CHANNEL_H

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import "SGControlChannelProtocol.h"

/**
 * SGControlChannel, the single class through which every cross-process
 * control message in this project flows. One instance plays the server role 
 * Another instance plays the client role.
 */

@class SGControlChannel;

/** Block Types */

/**
 * Server-side handler invoked when a request of the registered messageType
 * arrives.  The handler MUST call exactly one of reply (success) or
 * replyError (failure) before returning or scheduling work, failing to do
 * so leaves the requesting client blocked until its timeout fires.
 */
typedef void (^SGControlReplyBlock)(SGControlMessageType type, NSData *payloadOrNil);
typedef void (^SGControlReplyErrorBlock)(SGControlError error, NSString *detailOrNil);
typedef void (^SGControlMessageHandler)(const SGControlChannelMessage *request,
                                         SGControlReplyBlock reply,
                                         SGControlReplyErrorBlock replyError);

/**
 * Client-side completion for sendRequest:.  Exactly one of error == OK with
 * a non-NULL response, or error != OK with a NULL response.  The response
 * envelope is valid only for the duration of the completion call.
 */
typedef void (^SGControlClientCompletion)(SGControlError error,
                                           const SGControlChannelMessage *responseOrNull);

/**
 * Client-side handler for subscribed events.  data is the event-specific
 * payload (one of the SGCxxxEventData structs) wrapped as NSData, or nil for
 * empty-payload events.  Fires on the global concurrent queue.
 */
typedef void (^SGControlEventHandler)(SGControlEventType eventType, NSData *dataOrNil);

/**
 * Completion for subscribeToEvent:.  On success, subscriptionId is the
 * server-assigned handle to pass to unsubscribe: later.  On failure,
 * subscriptionId is zero.
 */
typedef void (^SGControlSubscribeCompletion)(SGControlError error, uint64_t subscriptionId);

/**
 * Client-side connection-state observer.
 */
typedef void (^SGControlConnectionHandler)(BOOL connected);

@interface SGControlChannel : NSObject

/** Construction */

/**
 * Server role.  serviceName is the bootstrap-registered name the peer will
 * look up.  The instance is inert until -start is called.
 */
+ (instancetype)serverWithServiceName:(const char *)serviceName;

/**
 * Client role.  serviceName is the bootstrap name of the peer's service.
 * The instance is inert until -start is called.
 */
+ (instancetype)clientForServiceName:(const char *)serviceName;

/** Lifecycle */

/**
 * Brings the channel up.  For a server: allocates the receive port,
 * registers it with bootstrap, starts the receive loop.  For a client:
 * allocates the reply port, looks up the server, starts the receive loop.
 */
- (BOOL)start;

/**
 * Tears the channel down.  Cancels pending requests with SGCERR_UNREACHABLE,
 * fires no further event handlers, joins the receive thread, deallocates
 * Mach ports.  Safe to call from any thread; idempotent.
 */
- (void)stop;

/** Server API */

/**
 * Registers a handler for incoming requests of the given messageType.
 * Replaces any previously registered handler for the same type.  Must be
 * called after -start.  Server role only.
 */
- (void)registerHandler:(SGControlMessageHandler)handler
         forMessageType:(SGControlMessageType)messageType;

/**
 * Broadcasts an event to every subscriber currently subscribed to eventType.
 * payload is the event-specific data (matching one of the SGCxxxEventData
 * structs) or nil for empty-payload events.  Subscribers whose reply port
 * has died are silently pruned.  Server role only.
 */
- (void)postEvent:(SGControlEventType)eventType
          payload:(NSData *)payloadOrNil;

/** Client API */

/**
 * Sends a request to the server and invokes completion with the response or
 * an error.  If the channel is not currently connected, the request is
 * queued and replayed on reconnect.
 */
- (void)sendRequest:(SGControlMessageType)messageType
            payload:(NSData *)payloadOrNil
            timeout:(NSTimeInterval)timeout
         completion:(SGControlClientCompletion)completion;

/**
 * Subscribes to server-side events of the given type.  Completion fires
 * once the server acknowledges with a subscription id.
 */
- (void)subscribeToEvent:(SGControlEventType)eventType
                 handler:(SGControlEventHandler)handler
              completion:(SGControlSubscribeCompletion)completion;

/**
 * Cancels a subscription previously created via subscribeToEvent:.  Unknown
 * ids are silently ignored. Client role only.
 */
- (void)unsubscribe:(uint64_t)subscriptionId;

/**
 * Installs a single connection-state handler called whenever the underlying
 * Mach connection to the peer transitions between connected and disconnected
 * states.  Replaces any previously installed handler.
 */
- (void)setConnectionHandler:(SGControlConnectionHandler)handler;

/** Introspection */

/**
 * YES if the channel currently has a live connection to the peer.  For a
 * server, YES once -start has succeeded.  For a client, YES once
 * bootstrap_look_up has returned a valid port and no dead-name notification
 * has invalidated it.
 */
- (BOOL)isConnected;

@end

#endif
