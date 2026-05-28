#import "SGControlChannel.h"
#import "SGLog.h"
#include <bootstrap.h>
#include <pthread.h>
#include <string.h>
#include <stddef.h>

/* MRC/ARC bridge: daemon + SB tweak are MRC, prefs bundle is ARC.  ARC
 * collapses these to no-ops; under MRC they emit the explicit calls.
 * dispatch_release is guarded the same way (forbidden under OS_OBJECT_USE_OBJC). */
#if __has_feature(objc_arc)
  #define SGC_RELEASE(x)            do { (void)(x); } while (0)
  #define SGC_RETAIN(x)             (x)
  #define SGC_AUTORELEASE(x)        (x)
  #define SGC_PIN(x)                do { (void)(x); } while (0)
  #define SGC_DISPATCH_RELEASE(x)   do { (void)(x); } while (0)
#else
  #define SGC_RELEASE(x)            [(x) release]
  #define SGC_RETAIN(x)             [(x) retain]
  #define SGC_AUTORELEASE(x)        [(x) autorelease]
  #define SGC_PIN(x)                [[(x) retain] autorelease]
  #define SGC_DISPATCH_RELEASE(x)   dispatch_release(x)
#endif

/* Timing bounds are shared with callers via SGControlChannelProtocol.h. */
#define kSGCDefaultTimeoutSec    SG_CONTROL_DEFAULT_REQUEST_TIMEOUT_SEC
#define kSGCSendTimeoutMs        ((mach_msg_timeout_t)SG_CONTROL_SEND_TIMEOUT_MS)

#define SGC_RECV_TRAILER_BYTES   256     // kernel-trailer padding for mach_msg recv
#define SGC_RECV_BACKOFF_USEC    10000   // recv-loop nap when port is transiently NULL

@implementation SGControlChannel {
    BOOL                   _isServer;
    char                  *_serviceName;          /* strdup'd; freed in dealloc */

    BOOL                   _started;
    volatile BOOL          _stopping;

    /* Server-only state */
    mach_port_t            _servicePort;          /* receive right, bootstrap-registered */
    NSMutableDictionary   *_handlers;             /* @(SGControlMessageType) -> [Block copy] */
    NSMutableSet          *_clientPorts;          /* @(mach_port_t) — held send rights to client reply ports */
    NSMutableDictionary   *_subscriptions;        /* @(subId) -> @{@"port":@(port), @"event":@(SGControlEventType)} */
    uint64_t               _nextSubscriptionId;

    /* Client-only state */
    mach_port_t            _replyPort;            /* receive right */
    mach_port_t            _serverPort;           /* send right; MACH_PORT_NULL while disconnected */
    BOOL                   _connected;
    NSMutableDictionary   *_pendingRequests;     /* @(reqId) -> @{completion, timeoutSource, timeoutDeadline} */
    NSMutableDictionary   *_eventHandlers;       /* @(subId) -> [Block copy] */
    NSMutableArray        *_pendingQueue;        /* requests issued while disconnected, replayed on connect */
    uint64_t               _nextRequestId;
    uint32_t               _lookupFailureCount;
    SGControlConnectionHandler _connectionHandler;

    /* Receive thread */
    pthread_t              _recvThread;
    BOOL                   _recvThreadCreated;

    /* Serial queue protecting all mutable state.  Receive thread dispatches
     * incoming messages here; public API methods dispatch state mutations
     * here.  Caller handlers (completions, event handlers) are fanned out
     * to the global concurrent queue from inside, so they never hold the
     * state queue. */
    dispatch_queue_t       _stateQueue;
}

#pragma mark - C Helpers

/* COPY_SEND preserves the right (server retains for later events); MOVE_SEND
 * consumes it.  msgh_id mirrors messageType so receivers can demux without
 * parsing the payload. */
static kern_return_t SGCSendMessage(mach_port_t remotePort,
                                     mach_msg_type_name_t remoteDisposition,
                                     mach_port_t replyPortOrZero,
                                     SGControlMessageType type,
                                     uint16_t eventType,
                                     uint16_t errorCode,
                                     uint64_t requestId,
                                     uint64_t subscriptionId,
                                     const void *payloadBytes,
                                     uint32_t payloadLength) {
    if (payloadLength > SG_CONTROL_MAX_PAYLOAD) return KERN_RESOURCE_SHORTAGE;

    SGControlChannelMessage msg;
    memset(&msg, 0, sizeof(msg));

    msg.mach_header.msgh_bits = MACH_MSGH_BITS(remoteDisposition,
        replyPortOrZero != MACH_PORT_NULL ? MACH_MSG_TYPE_MAKE_SEND : 0);
    msg.mach_header.msgh_remote_port = remotePort;
    msg.mach_header.msgh_local_port  = replyPortOrZero;
    msg.mach_header.msgh_id          = (mach_msg_id_t)type;

    msg.magic          = SG_CONTROL_MAGIC;
    msg.version        = SG_CONTROL_VERSION;
    msg.flags          = 0;
    msg.messageType    = (uint8_t)type;
    msg.eventType      = eventType;
    msg.errorCode      = errorCode;
    msg.requestId      = requestId;
    msg.subscriptionId = subscriptionId;
    msg.payloadLength  = payloadLength;
    if (payloadBytes && payloadLength > 0) memcpy(msg.payload, payloadBytes, payloadLength);

    size_t size = offsetof(SGControlChannelMessage, payload) + payloadLength;
    size = (size + 3) & ~(size_t)3;
    msg.mach_header.msgh_size = (mach_msg_size_t)size;

    return mach_msg(&msg.mach_header,
                    MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                    msg.mach_header.msgh_size,
                    0, MACH_PORT_NULL, kSGCSendTimeoutMs, MACH_PORT_NULL);
}

static void SGCCopyCString(char *dst, size_t dstSize, const char *src) {
    if (!dst || dstSize == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t i = 0;
    while (i + 1 < dstSize && src[i] != '\0') {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

static void *SGCRecvThreadEntry(void *arg) {
    SGControlChannel *self = (__bridge SGControlChannel *)arg;
    [self _runReceiveLoop];
    return NULL;
}

#pragma mark - Construction

+ (instancetype)serverWithServiceName:(const char *)serviceName {
    return SGC_AUTORELEASE([[self alloc] initWithServiceName:serviceName isServer:YES]);
}

+ (instancetype)clientForServiceName:(const char *)serviceName {
    return SGC_AUTORELEASE([[self alloc] initWithServiceName:serviceName isServer:NO]);
}

- (instancetype)initWithServiceName:(const char *)serviceName isServer:(BOOL)isServer {
    if (!serviceName || serviceName[0] == '\0') { SGC_RELEASE(self); return nil; }
    if ((self = [super init])) {
        _isServer = isServer;
        _serviceName = strdup(serviceName);
        _stateQueue = dispatch_queue_create("com.skyglow.controlchannel.state", DISPATCH_QUEUE_SERIAL);
        if (isServer) {
            _handlers      = [[NSMutableDictionary alloc] init];
            _clientPorts   = [[NSMutableSet alloc] init];
            _subscriptions = [[NSMutableDictionary alloc] init];
            _nextSubscriptionId = 1;
        } else {
            _pendingRequests = [[NSMutableDictionary alloc] init];
            _eventHandlers   = [[NSMutableDictionary alloc] init];
            _pendingQueue    = [[NSMutableArray alloc] init];
            _nextRequestId   = 1;
        }
    }
    return self;
}

- (void)dealloc {
    if (_started && !_stopping) [self stop];
    if (_serviceName) free(_serviceName);
    SGC_RELEASE(_handlers);
    SGC_RELEASE(_clientPorts);
    SGC_RELEASE(_subscriptions);
    SGC_RELEASE(_pendingRequests);
    SGC_RELEASE(_eventHandlers);
    SGC_RELEASE(_pendingQueue);
    SGC_RELEASE(_connectionHandler);
    if (_stateQueue) SGC_DISPATCH_RELEASE(_stateQueue);
#if !__has_feature(objc_arc)
    [super dealloc];
#endif
}

#pragma mark - Lifecycle

- (BOOL)start {
    __block BOOL ok = NO;
    dispatch_sync(_stateQueue, ^{
        if (_started) { ok = YES; return; }

        if (_isServer) {
            kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &_servicePort);
            if (kr != KERN_SUCCESS) {
                SGLOGE(SGControlChannel, "code=%s role=server service=%s operation=mach_port_allocate kr=%d result=failed", SGND_CONTROL_SERVER_PORT_FAILED,
                            _serviceName, kr);
                return;
            }
            kr = mach_port_insert_right(mach_task_self(), _servicePort, _servicePort, MACH_MSG_TYPE_MAKE_SEND);
            if (kr != KERN_SUCCESS) {
                SGLOGE(SGControlChannel, "code=%s role=server service=%s operation=mach_port_insert_right kr=%d result=failed", SGND_CONTROL_SERVER_PORT_FAILED,
                            _serviceName, kr);
                mach_port_mod_refs(mach_task_self(), _servicePort, MACH_PORT_RIGHT_RECEIVE, -1);
                _servicePort = MACH_PORT_NULL;
                return;
            }
            mach_port_t bsPort = MACH_PORT_NULL;
            task_get_bootstrap_port(mach_task_self(), &bsPort);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            kr = bootstrap_register(bsPort, _serviceName, _servicePort);
#pragma clang diagnostic pop
            if (kr != KERN_SUCCESS) {
                SGLOGE(SGControlChannel, "code=%s role=server service=%s operation=bootstrap_register kr=%d result=failed", SGND_CONTROL_SERVER_PORT_FAILED,
                            _serviceName, kr);
                mach_port_mod_refs(mach_task_self(), _servicePort, MACH_PORT_RIGHT_RECEIVE, -1);
                _servicePort = MACH_PORT_NULL;
                return;
            }
            SGLOGI(SGControlChannel, "code=%s role=server service=%s result=listening", SGND_CONTROL_SERVER_READY, _serviceName);
        } else {
            kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &_replyPort);
            if (kr != KERN_SUCCESS) {
                SGLOGE(SGControlChannel, "code=%s role=client service=%s operation=mach_port_allocate kr=%d result=failed", SGND_CONTROL_CLIENT_PORT_FAILED,
                            _serviceName, kr);
                return;
            }
            kr = mach_port_insert_right(mach_task_self(), _replyPort, _replyPort, MACH_MSG_TYPE_MAKE_SEND);
            if (kr != KERN_SUCCESS) {
                SGLOGE(SGControlChannel, "code=%s role=client service=%s operation=mach_port_insert_right kr=%d result=failed", SGND_CONTROL_CLIENT_PORT_FAILED,
                            _serviceName, kr);
                mach_port_mod_refs(mach_task_self(), _replyPort, MACH_PORT_RIGHT_RECEIVE, -1);
                _replyPort = MACH_PORT_NULL;
                return;
            }
            [self _clientAttemptLookupLocked];
            /* Client returns YES even if first lookup failed — reconnect is internal. */
        }

        _started = YES;
        pthread_create(&_recvThread, NULL, SGCRecvThreadEntry, (__bridge void *)self);
        _recvThreadCreated = YES;
        ok = YES;
    });
    return ok;
}

- (void)stop {
    __block BOOL needsJoin = NO;
    dispatch_sync(_stateQueue, ^{
        if (_stopping) return;
        _stopping = YES;

        /* Fail every in-flight pending request so callers unblock. */
        if (!_isServer) {
            NSDictionary *snapshot = SGC_AUTORELEASE([_pendingRequests copy]);
            [_pendingRequests removeAllObjects];
            for (NSNumber *rid in snapshot) {
                NSDictionary *entry = snapshot[rid];
                SGControlClientCompletion comp = (SGControlClientCompletion)entry[@"completion"];
                if (comp) {
                    SGControlClientCompletion compCopy = SGC_AUTORELEASE([comp copy]);
                    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                        compCopy(SGCERR_UNREACHABLE, NULL);
                    });
                }
            }
            [_pendingQueue removeAllObjects];
        }

        /* Dropping the receive right unblocks mach_msg with MACH_RCV_PORT_DIED
         * so the recv thread sees _stopping and exits. */
        if (_isServer && _servicePort != MACH_PORT_NULL) {
            mach_port_mod_refs(mach_task_self(), _servicePort, MACH_PORT_RIGHT_SEND, -1);
            mach_port_mod_refs(mach_task_self(), _servicePort, MACH_PORT_RIGHT_RECEIVE, -1);
            _servicePort = MACH_PORT_NULL;
        }
        if (!_isServer && _replyPort != MACH_PORT_NULL) {
            mach_port_mod_refs(mach_task_self(), _replyPort, MACH_PORT_RIGHT_SEND, -1);
            mach_port_mod_refs(mach_task_self(), _replyPort, MACH_PORT_RIGHT_RECEIVE, -1);
            _replyPort = MACH_PORT_NULL;
        }
        if (!_isServer && _serverPort != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), _serverPort);
            _serverPort = MACH_PORT_NULL;
            _connected = NO;
        }
        if (_isServer) {
            for (NSNumber *portNum in _clientPorts) {
                mach_port_deallocate(mach_task_self(), (mach_port_t)[portNum unsignedIntValue]);
            }
            [_clientPorts removeAllObjects];
            [_subscriptions removeAllObjects];
        }

        needsJoin = _recvThreadCreated;
        _recvThreadCreated = NO;
    });

    if (needsJoin) pthread_join(_recvThread, NULL);
}

#pragma mark - Server API

- (void)registerHandler:(SGControlMessageHandler)handler forMessageType:(SGControlMessageType)messageType {
    if (!_isServer) {
        SGLOGE(SGControlChannel, "code=%s method=registerHandler role=client result=ignored", SGND_CONTROL_API_MISUSE);
        return;
    }
    SGControlMessageHandler copied = [handler copy];
    dispatch_async(_stateQueue, ^{
        _handlers[@(messageType)] = copied;
        SGC_RELEASE(copied);
    });
}

- (void)postEvent:(SGControlEventType)eventType payload:(NSData *)payloadOrNil {
    if (!_isServer) {
        SGLOGE(SGControlChannel, "code=%s method=postEvent role=client result=ignored", SGND_CONTROL_API_MISUSE);
        return;
    }

    NSUInteger dataLen = MIN([payloadOrNil length], (NSUInteger)SG_CONTROL_MAX_EVENT_DATA_SIZE);
    SGCEventDeliveryPayload deliveryPayload;
    memset(&deliveryPayload, 0, sizeof(deliveryPayload));
    deliveryPayload.eventType = eventType;
    deliveryPayload.dataLength = (uint32_t)dataLen;
    if (dataLen > 0) memcpy(deliveryPayload.data, [payloadOrNil bytes], dataLen);

    NSData *payloadCopy = [[NSData alloc] initWithBytes:&deliveryPayload
                                                 length:offsetof(SGCEventDeliveryPayload, data) + dataLen];

    dispatch_async(_stateQueue, ^{
        NSArray *subIds = [_subscriptions allKeys];
        for (NSNumber *subId in subIds) {
            NSDictionary *sub = _subscriptions[subId];
            if ([sub[@"event"] unsignedShortValue] != eventType) continue;
            mach_port_t port = (mach_port_t)[sub[@"port"] unsignedIntValue];

            kern_return_t kr = SGCSendMessage(port, MACH_MSG_TYPE_COPY_SEND, MACH_PORT_NULL,
                                              SGCMSG_EVENT_DELIVERY, eventType, 0,
                                              0, [subId unsignedLongLongValue],
                                              [payloadCopy bytes], (uint32_t)[payloadCopy length]);
            if (kr != KERN_SUCCESS) {
                SGLOGW(SGControlChannel, "code=%s event=%u subscription=%llu kr=%d action=prune", SGND_CONTROL_EVENT_SEND_FAILED,
                            eventType, [subId unsignedLongLongValue], kr);
                [_subscriptions removeObjectForKey:subId];
            }
        }
        SGC_RELEASE(payloadCopy);
    });
}

#pragma mark - Client API

- (void)sendRequest:(SGControlMessageType)messageType
            payload:(NSData *)payloadOrNil
            timeout:(NSTimeInterval)timeout
         completion:(SGControlClientCompletion)completion {
    if (_isServer) {
        SGLOGE(SGControlChannel, "code=%s method=sendRequest role=server result=ignored", SGND_CONTROL_API_MISUSE);
        if (completion) completion(SGCERR_INVALID_REQUEST, NULL);
        return;
    }
    if (timeout <= 0) timeout = kSGCDefaultTimeoutSec;

    NSData *payloadCopy = [payloadOrNil copy];
    SGControlClientCompletion compCopy = [completion copy];

    dispatch_async(_stateQueue, ^{
        if (_stopping) {
            if (compCopy) dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                compCopy(SGCERR_UNREACHABLE, NULL);
            });
            SGC_RELEASE(compCopy);
            SGC_RELEASE(payloadCopy);
            return;
        }

        uint64_t rid = _nextRequestId++;
        [self _clientRegisterPendingRequestLocked:rid timeout:timeout completion:compCopy];

        if (!_connected) {
            [self _clientAttemptLookupLocked];
        }

        if (_connected) {
            [self _clientDispatchRequestLocked:rid type:messageType payload:payloadCopy];
        } else {
            NSMutableDictionary *queued = [NSMutableDictionary dictionary];
            queued[@"rid"] = @(rid);
            queued[@"type"] = @(messageType);
            if (payloadCopy) queued[@"payload"] = payloadCopy;
            [_pendingQueue addObject:queued];
        }

        SGC_RELEASE(compCopy);
        SGC_RELEASE(payloadCopy);
    });
}

- (void)subscribeToEvent:(SGControlEventType)eventType
                 handler:(SGControlEventHandler)handler
              completion:(SGControlSubscribeCompletion)completion {
    if (_isServer) {
        SGLOGE(SGControlChannel, "code=%s method=subscribeToEvent role=server result=ignored", SGND_CONTROL_API_MISUSE);
        if (completion) completion(SGCERR_INVALID_REQUEST, 0);
        return;
    }

    SGControlEventHandler handlerCopy = [handler copy];
    SGControlSubscribeCompletion compCopy = [completion copy];

    SGCSubscribePayload payload;
    memset(&payload, 0, sizeof(payload));
    payload.eventType = eventType;
    NSData *payloadData = [NSData dataWithBytes:&payload length:sizeof(payload)];

    [self sendRequest:SGCMSG_SUBSCRIBE payload:payloadData timeout:kSGCDefaultTimeoutSec
           completion:^(SGControlError err, const SGControlChannelMessage *response) {
        if (err != SGCERR_OK || !response) {
            if (compCopy) compCopy(err == SGCERR_OK ? SGCERR_INTERNAL : err, 0);
        } else {
            uint64_t subId = response->subscriptionId;
            SGControlEventHandler handlerRetained = SGC_RETAIN(handlerCopy);
            dispatch_async(_stateQueue, ^{
                _eventHandlers[@(subId)] = handlerRetained;
                SGC_RELEASE(handlerRetained);
            });
            if (compCopy) compCopy(SGCERR_OK, subId);
        }
        SGC_RELEASE(handlerCopy);
        SGC_RELEASE(compCopy);
    }];
}

- (void)setConnectionHandler:(SGControlConnectionHandler)handler {
    if (_isServer) {
        SGLOGE(SGControlChannel, "code=%s method=setConnectionHandler role=server result=ignored", SGND_CONTROL_API_MISUSE);
        return;
    }
    SGControlConnectionHandler copied = [handler copy];
    dispatch_async(_stateQueue, ^{
        SGC_RELEASE(_connectionHandler);
        _connectionHandler = copied;
    });
}

- (void)unsubscribe:(uint64_t)subscriptionId {
    if (_isServer) return;
    SGCUnsubscribePayload payload;
    memset(&payload, 0, sizeof(payload));
    payload.subscriptionId = subscriptionId;
    NSData *payloadData = [NSData dataWithBytes:&payload length:sizeof(payload)];

    [self sendRequest:SGCMSG_UNSUBSCRIBE payload:payloadData timeout:kSGCDefaultTimeoutSec
           completion:^(SGControlError err, const SGControlChannelMessage *response) {
        dispatch_async(_stateQueue, ^{
            [_eventHandlers removeObjectForKey:@(subscriptionId)];
        });
    }];
}

#pragma mark - Introspection

- (BOOL)isConnected {
    __block BOOL c = NO;
    dispatch_sync(_stateQueue, ^{
        c = _isServer ? _started : (_connected && !_stopping);
    });
    return c;
}

#pragma mark - Receive Loop

- (void)_runReceiveLoop {
    const size_t bufSize = sizeof(SGControlChannelMessage) + SGC_RECV_TRAILER_BYTES;

    while (!_stopping) {
        mach_port_t port = _isServer ? _servicePort : _replyPort;
        if (port == MACH_PORT_NULL) {
            /* Port destroyed by stop or by a reconnect cycle in progress. */
            usleep(SGC_RECV_BACKOFF_USEC);
            continue;
        }

        SGControlChannelMessage *msg = (SGControlChannelMessage *)malloc(bufSize);
        if (!msg) { usleep(SGC_RECV_BACKOFF_USEC); continue; }
        memset(msg, 0, bufSize);

        kern_return_t kr = mach_msg(&msg->mach_header, MACH_RCV_MSG, 0,
                                    (mach_msg_size_t)bufSize, port,
                                    MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            free(msg);
            if (_stopping) break;
            /* MACH_RCV_PORT_DIED/CHANGED during stop/reconnect; transient
             * errors are also benign — re-check the port next iteration. */
            continue;
        }

        SGControlChannelMessage *ownedMsg = msg;
        dispatch_async(_stateQueue, ^{
            [self _dispatchIncomingMessageLocked:ownedMsg];
            free(ownedMsg);
        });
    }
}

- (void)_dispatchIncomingMessageLocked:(SGControlChannelMessage *)msg {
    if (_stopping) return;

    mach_msg_id_t mid = msg->mach_header.msgh_id;

    /* Dead-name body is mach_dead_name_notification_t, not our envelope —
     * recognise by id alone and never read SGControlChannel fields from it. */
    if (mid == MACH_NOTIFY_DEAD_NAME) {
        if (_isServer) [self _serverHandleDeadNameLocked:msg];
        else           [self _clientHandleDeadNameLocked:msg];
        return;
    }

    if (msg->magic != SG_CONTROL_MAGIC || msg->version != SG_CONTROL_VERSION) {
        SGLOGW(SGControlChannel, "code=%s magic=0x%02x version=0x%02x message_id=%d action=discard", SGND_CONTROL_ENVELOPE_MALFORMED,
                    msg->magic, msg->version, mid);
        return;
    }

    /* Frame consistency: payloadLength must fit both the hard wire cap AND
     * the actual received Mach message size.  The kernel sets msgh_size on
     * receive to the number of bytes actually delivered, so a peer can't
     * forge it the way they can forge payloadLength.  Without this check, a
     * peer can claim payloadLength=4096 while sending a few hundred bytes;
     * downstream handlers then process up to 4096 bytes of memset-zero
     * memory as legitimate payload.  Currently safe-by-luck because every
     * downstream validator rejects zero-filled inputs, but defense at the
     * parser boundary is what stopped yesterday's protocol bugs and we
     * want the same property here. */
    {
        mach_msg_size_t machSize = msg->mach_header.msgh_size;
        size_t envelopeSize = offsetof(SGControlChannelMessage, payload);
        if (machSize < envelopeSize) {
            SGLOGW(SGControlChannel,
                   "code=%s reason=truncated_envelope mach_size=%u envelope_size=%lu action=discard",
                   SGND_CONTROL_ENVELOPE_MALFORMED, (unsigned)machSize, (unsigned long)envelopeSize);
            return;
        }
        size_t maxAllowedPayload = (size_t)machSize - envelopeSize;
        if (msg->payloadLength > SG_CONTROL_MAX_PAYLOAD ||
            msg->payloadLength > maxAllowedPayload) {
            SGLOGW(SGControlChannel,
                   "code=%s reason=payload_length_inconsistent claimed=%u available=%lu action=discard",
                   SGND_CONTROL_ENVELOPE_MALFORMED,
                   msg->payloadLength, (unsigned long)maxAllowedPayload);
            return;
        }
    }

    if (_isServer) {
        [self _serverDispatchRequestLocked:msg];
    } else {
        if (msg->messageType == SGCMSG_EVENT_DELIVERY) [self _clientDispatchEventLocked:msg];
        else                                            [self _clientDispatchResponseLocked:msg];
    }
}

#pragma mark - Server-Side Dispatch

- (void)_serverDispatchRequestLocked:(SGControlChannelMessage *)msg {
    mach_port_t replyPort = msg->mach_header.msgh_remote_port;
    SGControlMessageType type = (SGControlMessageType)msg->messageType;
    uint64_t requestId = msg->requestId;

    /* First request from this client: retain the send right + register a
     * dead-name notification.  Subsequent requests just drop the duplicate
     * send right we received. */
    NSNumber *portKey = @(replyPort);
    if (![_clientPorts containsObject:portKey]) {
        [_clientPorts addObject:portKey];
        mach_port_t prev = MACH_PORT_NULL;
        mach_port_request_notification(mach_task_self(), replyPort, MACH_NOTIFY_DEAD_NAME, 0,
                                       _servicePort, MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev);
        if (prev != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), prev);
    } else {
        mach_port_deallocate(mach_task_self(), replyPort);
    }

    /* Built-in SUBSCRIBE / UNSUBSCRIBE handling lives inside the channel. */
    if (type == SGCMSG_SUBSCRIBE) {
        [self _serverHandleSubscribeLocked:msg replyPort:replyPort];
        return;
    }
    if (type == SGCMSG_UNSUBSCRIBE) {
        [self _serverHandleUnsubscribeLocked:msg replyPort:replyPort];
        return;
    }

    SGControlMessageHandler handler = _handlers[@(type)];
    if (!handler) {
        SGLOGW(SGControlChannel, "code=%s type=0x%02x result=invalid_request", SGND_CONTROL_HANDLER_MISSING, type);
        SGCErrorResponsePayload err;
        memset(&err, 0, sizeof(err));
        SGCCopyCString(err.message, sizeof(err.message), "unknown message type");
        SGCSendMessage(replyPort, MACH_MSG_TYPE_COPY_SEND, MACH_PORT_NULL,
                       SGCMSG_ERROR_RESPONSE, 0, SGCERR_INVALID_REQUEST,
                       requestId, 0, &err, sizeof(err));
        return;
    }

    /* Heap-copy the request so it outlives the state-queue frame; the
     * dispatched block owns its lifetime and frees regardless of whether
     * the handler responds. */
    SGControlChannelMessage *requestCopy = (SGControlChannelMessage *)malloc(sizeof(*msg));
    memcpy(requestCopy, msg, sizeof(*msg));

    SGControlReplyBlock reply = ^(SGControlMessageType respType, NSData *respPayload) {
        SGCSendMessage(replyPort, MACH_MSG_TYPE_COPY_SEND, MACH_PORT_NULL,
                       respType, 0, 0, requestId, 0,
                       [respPayload bytes], (uint32_t)[respPayload length]);
    };
    SGControlReplyErrorBlock replyError = ^(SGControlError errCode, NSString *detail) {
        SGCErrorResponsePayload payload;
        memset(&payload, 0, sizeof(payload));
        if (detail) SGCCopyCString(payload.message, sizeof(payload.message), [detail UTF8String]);
        SGCSendMessage(replyPort, MACH_MSG_TYPE_COPY_SEND, MACH_PORT_NULL,
                       SGCMSG_ERROR_RESPONSE, 0, (uint16_t)errCode, requestId, 0,
                       &payload, sizeof(payload));
    };

    SGControlMessageHandler handlerCopy = SGC_RETAIN(handler);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        handlerCopy(requestCopy, reply, replyError);
        free(requestCopy);
        SGC_RELEASE(handlerCopy);
    });
}

- (void)_serverHandleSubscribeLocked:(SGControlChannelMessage *)msg replyPort:(mach_port_t)replyPort {
    if (msg->payloadLength < sizeof(SGCSubscribePayload)) {
        SGCErrorResponsePayload err; memset(&err, 0, sizeof(err));
        SGCCopyCString(err.message, sizeof(err.message), "subscribe payload too short");
        SGCSendMessage(replyPort, MACH_MSG_TYPE_COPY_SEND, MACH_PORT_NULL,
                       SGCMSG_ERROR_RESPONSE, 0, SGCERR_INVALID_REQUEST, msg->requestId, 0,
                       &err, sizeof(err));
        return;
    }
    SGCSubscribePayload *sub = (SGCSubscribePayload *)msg->payload;
    uint64_t subId = _nextSubscriptionId++;
    _subscriptions[@(subId)] = @{ @"port": @(replyPort), @"event": @(sub->eventType) };
    SGCSendMessage(replyPort, MACH_MSG_TYPE_COPY_SEND, MACH_PORT_NULL,
                   SGCMSG_GENERIC_ACK, 0, 0, msg->requestId, subId,
                   NULL, 0);
}

- (void)_serverHandleUnsubscribeLocked:(SGControlChannelMessage *)msg replyPort:(mach_port_t)replyPort {
    if (msg->payloadLength >= sizeof(SGCUnsubscribePayload)) {
        SGCUnsubscribePayload *unsub = (SGCUnsubscribePayload *)msg->payload;
        [_subscriptions removeObjectForKey:@(unsub->subscriptionId)];
    }
    SGCSendMessage(replyPort, MACH_MSG_TYPE_COPY_SEND, MACH_PORT_NULL,
                   SGCMSG_GENERIC_ACK, 0, 0, msg->requestId, 0, NULL, 0);
}

- (void)_serverHandleDeadNameLocked:(SGControlChannelMessage *)msg {
    /**
     * mach_dead_name_notification_t carries the dying port name in the
     * first port descriptor.  We use a tolerant read against our envelope's
     * payload area since the wire format is compact and the field offsets
     * are stable across Mach versions.
     */
    mach_dead_name_notification_t *note = (mach_dead_name_notification_t *)msg;
    mach_port_t deadPort = note->not_port;

    SGLOGI(SGControlChannel, "code=%s role=server port=%u action=prune", SGND_CONTROL_CLIENT_DIED, deadPort);

    NSNumber *portKey = @(deadPort);
    if ([_clientPorts containsObject:portKey]) {
        mach_port_deallocate(mach_task_self(), deadPort);
        [_clientPorts removeObject:portKey];
    }
    NSArray *subIds = [_subscriptions allKeys];
    for (NSNumber *sid in subIds) {
        if ([_subscriptions[sid][@"port"] unsignedIntValue] == deadPort) {
            [_subscriptions removeObjectForKey:sid];
        }
    }
}

#pragma mark - Client-Side Dispatch

- (void)_clientAttemptLookupLocked {
    if (_stopping || _connected) return;

    mach_port_t bsPort = MACH_PORT_NULL;
    task_get_bootstrap_port(mach_task_self(), &bsPort);
    mach_port_t serverPort = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bsPort, _serviceName, &serverPort);
    if (kr != KERN_SUCCESS) {
        _lookupFailureCount++;
        if (_lookupFailureCount == 1) {
            SGLOGW(SGControlChannel, "code=%s role=client service=%s kr=%d action=wait_for_request", SGND_CONTROL_LOOKUP_FAILED, _serviceName, kr);
        } else {
            SGLOGD(SGControlChannel, "code=%s role=client service=%s kr=%d attempt=%u action=wait_for_request", SGND_CONTROL_LOOKUP_RETRY,
                        _serviceName, kr, _lookupFailureCount);
        }
        _connected = NO;
        return;
    }

    _serverPort = serverPort;
    _connected = YES;
    if (_lookupFailureCount > 1) {
        SGLOGI(SGControlChannel, "code=%s role=client service=%s suppressed_retries=%u result=connected", SGND_CONTROL_LOOKUP_RECOVERED,
                    _serviceName, _lookupFailureCount - 1);
    }
    _lookupFailureCount = 0;

    /* Dead-name notification fires to our reply port if the server dies. */
    mach_port_t prev = MACH_PORT_NULL;
    mach_port_request_notification(mach_task_self(), _serverPort, MACH_NOTIFY_DEAD_NAME, 0,
                                   _replyPort, MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev);
    if (prev != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), prev);

    SGLOGI(SGControlChannel, "code=%s role=client service=%s port=%u result=connected", SGND_CONTROL_CONNECTED, _serviceName, _serverPort);

    if (_connectionHandler) {
        SGControlConnectionHandler handlerCopy = SGC_RETAIN(_connectionHandler);
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            handlerCopy(YES);
            SGC_RELEASE(handlerCopy);
        });
    }

    /* Replay queued requests in arrival order. */
    NSArray *queued = SGC_AUTORELEASE([_pendingQueue copy]);
    [_pendingQueue removeAllObjects];
    for (NSDictionary *entry in queued) {
        uint64_t rid = [entry[@"rid"] unsignedLongLongValue];
        SGControlMessageType type = (SGControlMessageType)[entry[@"type"] unsignedCharValue];
        NSData *payload = entry[@"payload"];
        [self _clientDispatchRequestLocked:rid type:type payload:payload];
    }
}

- (void)_clientDispatchRequestLocked:(uint64_t)requestId
                                type:(SGControlMessageType)type
                             payload:(NSData *)payload {
    if (_serverPort == MACH_PORT_NULL || !_connected) {
        NSMutableDictionary *queued = [NSMutableDictionary dictionary];
        queued[@"rid"] = @(requestId);
        queued[@"type"] = @(type);
        if (payload) queued[@"payload"] = payload;
        [_pendingQueue addObject:queued];
        return;
    }
    kern_return_t kr = SGCSendMessage(_serverPort, MACH_MSG_TYPE_COPY_SEND, _replyPort,
                                      type, 0, 0, requestId, 0,
                                      [payload bytes], (uint32_t)[payload length]);
    if (kr != KERN_SUCCESS) {
        SGLOGW(SGControlChannel, "code=%s role=client type=0x%02x kr=%d result=unreachable", SGND_CONTROL_SEND_FAILED, type, kr);
        [self _clientFailPendingRequestLocked:requestId error:SGCERR_UNREACHABLE];
        [self _clientMarkDisconnectedLocked];
    }
}

- (void)_clientMarkDisconnectedLocked {
    if (_serverPort != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), _serverPort);
        _serverPort = MACH_PORT_NULL;
    }

    BOOL wasConnected = _connected;
    _connected = NO;

    if (wasConnected && _connectionHandler) {
        SGControlConnectionHandler handlerCopy = SGC_RETAIN(_connectionHandler);
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            handlerCopy(NO);
            SGC_RELEASE(handlerCopy);
        });
    }

    NSArray *rids = [_pendingRequests allKeys];
    for (NSNumber *rid in rids) {
        [self _clientFailPendingRequestLocked:[rid unsignedLongLongValue] error:SGCERR_UNREACHABLE];
    }

    [_eventHandlers removeAllObjects];
}

- (void)_clientRegisterPendingRequestLocked:(uint64_t)requestId
                                    timeout:(NSTimeInterval)timeout
                                 completion:(SGControlClientCompletion)completion {
    SGControlClientCompletion compCopy = [completion copy];

    _pendingRequests[@(requestId)] = @{
        @"completion": (id)compCopy ?: (id)[NSNull null],
    };
    SGC_RELEASE(compCopy);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC)),
                   _stateQueue, ^{
        if (_pendingRequests[@(requestId)] != nil) {
            SGLOGW(SGControlChannel, "timeout: service=%s rid=%llu timeout=%.1fs", _serviceName, requestId, timeout);
            [self _clientFailPendingRequestLocked:requestId error:SGCERR_TIMEOUT];

            if (!_isServer && _connected) {
                SGLOGW(SGControlChannel, "timeout: marking channel disconnected for reconnect on next send");
                [self _clientMarkDisconnectedLocked];
            }
        }
    });
}

- (void)_clientRemoveQueuedRequestLocked:(uint64_t)requestId {
    for (NSInteger i = (NSInteger)[_pendingQueue count] - 1; i >= 0; i--) {
        NSDictionary *entry = [_pendingQueue objectAtIndex:(NSUInteger)i];
        if ([entry[@"rid"] unsignedLongLongValue] == requestId) {
            [_pendingQueue removeObjectAtIndex:(NSUInteger)i];
        }
    }
}

- (void)_clientFailPendingRequestLocked:(uint64_t)requestId error:(SGControlError)error {
    NSDictionary *entry = _pendingRequests[@(requestId)];
    if (!entry) return;
    SGC_PIN(entry);
    [_pendingRequests removeObjectForKey:@(requestId)];
    [self _clientRemoveQueuedRequestLocked:requestId];

    id comp = entry[@"completion"];
    if (comp && comp != [NSNull null]) {
        SGControlClientCompletion compCopy = [(SGControlClientCompletion)comp copy];
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            compCopy(error, NULL);
            SGC_RELEASE(compCopy);
        });
    }
}

- (void)_clientDispatchResponseLocked:(SGControlChannelMessage *)msg {
    uint64_t rid = msg->requestId;
    NSDictionary *entry = _pendingRequests[@(rid)];
    if (!entry) {
        SGLOGD(SGControlChannel, "code=%s role=client request=%llu action=ignore", SGND_CONTROL_UNKNOWN_RESPONSE, rid);
        return;
    }
    SGC_PIN(entry);
    [_pendingRequests removeObjectForKey:@(rid)];

    SGControlError err = (msg->messageType == SGCMSG_ERROR_RESPONSE)
        ? (SGControlError)msg->errorCode : SGCERR_OK;

    /* Heap-copy the response so the completion block can outlive this frame. */
    SGControlChannelMessage *responseCopy = (SGControlChannelMessage *)malloc(sizeof(*msg));
    memcpy(responseCopy, msg, sizeof(*msg));

    id comp = entry[@"completion"];
    if (comp && comp != [NSNull null]) {
        SGControlClientCompletion compCopy = [(SGControlClientCompletion)comp copy];
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            compCopy(err, responseCopy);
            free(responseCopy);
            SGC_RELEASE(compCopy);
        });
    } else {
        free(responseCopy);
    }
}

- (void)_clientDispatchEventLocked:(SGControlChannelMessage *)msg {
    uint64_t subId = msg->subscriptionId;
    SGControlEventHandler handler = _eventHandlers[@(subId)];
    if (!handler) {
        SGLOGD(SGControlChannel, "code=%s role=client subscription=%llu action=ignore", SGND_CONTROL_UNKNOWN_EVENT, subId);
        return;
    }

    if (msg->payloadLength < offsetof(SGCEventDeliveryPayload, data)) {
        SGLOGW(SGControlChannel, "code=%s role=client bytes=%u minimum=%lu action=ignore", SGND_CONTROL_EVENT_MALFORMED,
                    msg->payloadLength, (unsigned long)offsetof(SGCEventDeliveryPayload, data));
        return;
    }
    SGCEventDeliveryPayload *dp = (SGCEventDeliveryPayload *)msg->payload;
    SGControlEventType eventType = (SGControlEventType)dp->eventType;
    uint32_t dataLen = MIN(dp->dataLength, (uint32_t)SG_CONTROL_MAX_EVENT_DATA_SIZE);
    NSData *data = (dataLen > 0)
        ? [[NSData alloc] initWithBytes:dp->data length:dataLen]
        : nil;

    SGControlEventHandler handlerCopy = SGC_RETAIN(handler);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        handlerCopy(eventType, data);
        SGC_RELEASE(data);
        SGC_RELEASE(handlerCopy);
    });
}

- (void)_clientHandleDeadNameLocked:(SGControlChannelMessage *)msg {
    mach_dead_name_notification_t *note = (mach_dead_name_notification_t *)msg;
    if (note->not_port != _serverPort) {
        /* A different port died — not our server.  Deallocate and move on. */
        mach_port_deallocate(mach_task_self(), note->not_port);
        return;
    }

    SGLOGI(SGControlChannel, "code=%s role=client service=%s action=reconnect", SGND_CONTROL_PEER_DIED, _serviceName);
    [self _clientMarkDisconnectedLocked];
}

@end
