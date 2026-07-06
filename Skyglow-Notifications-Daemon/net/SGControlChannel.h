#ifndef SKYGLOW_SG_CONTROL_CHANNEL_H
#define SKYGLOW_SG_CONTROL_CHANNEL_H

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import "SGControlChannelProtocol.h"

/**
 * SGControlChannel — the single class through which every cross-process
 * control message in this project flows.  One instance plays the server role
 * (advertises a Mach service, accepts incoming requests, holds per-client
 * subscription state).  Another instance plays the client role (looks up the
 * service, opens a persistent connection, sends requests, receives events).
 * Same class, two construction paths.
 *
 * Lifecycle is connection-scoped.  When the underlying Mach port to the peer
 * dies — the daemon crashed, SpringBoard restarted, the tweak was unloaded —
 * a dead-name notification fires.  The server cleans up the dead client's
 * subscriptions; the client tears down its pending state.  The next outgoing
 * request attempts a fresh lookup before queueing.  Requests issued while
 * disconnected are replayed if a later request reconnects before they time
 * out; requests in flight at the moment of disconnect complete with
 * SGCERR_UNREACHABLE.
 *
 * Threading:
 *   - One internal pthread per channel runs the blocking mach_msg receive loop.
 *   - All mutation of channel state happens on a serial dispatch queue.
 *   - Public API methods are safe to call from any thread.
 *   - Caller-supplied blocks (handlers, completions) are dispatched to the
 *     global concurrent queue so they cannot deadlock the channel's internals.
 *
 * Memory: implemented in MRC so it can live in the daemon target.  Blocks
 * are Block_copy'd into the channel's internal state and released after they
 * fire or after the channel is stopped.
 */

@class SGControlChannel;

/** Block Types */

/**
 * Server-side handler invoked when a request of the registered messageType
 * arrives.  The handler MUST call exactly one of reply (success) or
 * replyError (failure) before returning or scheduling work — failing to do
 * so leaves the requesting client blocked until its timeout fires.  The
 * request envelope is valid only for the duration of the handler call; copy
 * any fields you need beyond that point.
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
 * Client-side connection-state observer.  Fires with connected=YES the first
 * time bootstrap_look_up succeeds (or on every successful reconnect after a
 * dead-name notification), and with connected=NO when the channel detects
 * the peer has gone away.  Use this to drive work that should only run while
 * the peer is reachable — for example, draining a local-pending queue as
 * soon as the SpringBoard tweak loads.  Fires on the global concurrent
 * queue; the handler must not assume any particular thread.
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
 * Returns NO if the initial bring-up fails terminally (server: port
 * allocation or registration); clients always return YES because reconnect
 * is internal and a missing peer is not a terminal condition.
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
 * queued and replayed on reconnect — completion fires only after the
 * request has been dispatched and either acknowledged or timed out.
 * timeout is an upper bound including any queue-wait time; pass 0 to use
 * the channel default (5 seconds).  Client role only.
 */
- (void)sendRequest:(SGControlMessageType)messageType
            payload:(NSData *)payloadOrNil
            timeout:(NSTimeInterval)timeout
         completion:(SGControlClientCompletion)completion;

/**
 * Subscribes to server-side events of the given type.  Completion fires
 * once the server acknowledges with a subscription id.  Subsequent events
 * of that type are delivered to handler until -unsubscribe: is called or
 * the connection drops (subscriptions do NOT auto-resubscribe on
 * reconnect — the caller decides whether re-subscription is appropriate
 * for their use case).  Client role only.
 */
- (void)subscribeToEvent:(SGControlEventType)eventType
                 handler:(SGControlEventHandler)handler
              completion:(SGControlSubscribeCompletion)completion;

/**
 * Cancels a subscription previously created via subscribeToEvent:.  Unknown
 * ids are silently ignored.  Client role only.
 */
- (void)unsubscribe:(uint64_t)subscriptionId;

/**
 * Installs a single connection-state handler called whenever the underlying
 * Mach connection to the peer transitions between connected and disconnected
 * states.  Replaces any previously installed handler.  Pass nil to remove.
 * Safe to call before or after -start.  Client role only.
 */
- (void)setConnectionHandler:(SGControlConnectionHandler)handler;

/** Introspection */

/**
 * YES if the channel currently has a live connection to the peer.  For a
 * server, YES once -start has succeeded.  For a client, YES once
 * bootstrap_look_up has returned a valid port and no dead-name notification
 * has invalidated it.  Useful for callers that want to gate work on a fresh
 * connection rather than queue through the pending-request machinery.
 */
- (BOOL)isConnected;

@end

#endif
