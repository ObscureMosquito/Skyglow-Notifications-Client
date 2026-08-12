#import "SGNotificationProcessor.h"
#import "SGCryptoEngine.h"
#import "SGDatabaseManager.h"
#import "SGLog.h"
#import "SGLogDiagnostics.h"
#import "SGPayloadParser.h"
#import "SGProtocolHandler.h"

static const int64_t    kSGDrainSafetyIntervalSec          = 300;
static const int64_t    kSGDrainSafetyLeewaySec            =  30;
static const int64_t    kSGLocalPendingFallbackDeadlineSec = 86400;
static const NSUInteger kSGSeenMessageIDCap                = 200;

static void SGCopyMessageIDHex(NSData *msgID, char *out, size_t outSize) {
    if (!out || outSize == 0) return;
    out[0] = '\0';
    if (![msgID length]) {
        strlcpy(out, "none", outSize);
        return;
    }

    const uint8_t *bytes = (const uint8_t *)[msgID bytes];
    NSUInteger length = MIN([msgID length], (NSUInteger)SGP_MSG_ID_LEN);
    size_t position = 0;
    for (NSUInteger i = 0; i < length && position + 2 < outSize; i++) {
        int written = snprintf(out + position, outSize - position,
                               "%02x", bytes[i]);
        if (written != 2) break;
        position += 2;
    }
    out[position] = '\0';
}

@implementation SGNotificationProcessor {
    SGNotificationDeliveryHandler _deliveryHandler;
    NSMutableOrderedSet *_seenMessageIDs;
    dispatch_queue_t _deliveryQueue;
    dispatch_source_t _retryTimer;
}

- (instancetype)initWithDeliveryHandler:(SGNotificationDeliveryHandler)handler {
    if ((self = [super init])) {
        _deliveryHandler = [handler copy];
        _seenMessageIDs = [[NSMutableOrderedSet alloc]
            initWithCapacity:kSGSeenMessageIDCap];
        _deliveryQueue = dispatch_queue_create(
            "com.skyglow.daemon.notification-delivery", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)dealloc {
    [self suspendPendingDeliveryRetries];
    dispatch_release(_deliveryQueue);
    [_seenMessageIDs release];
    [_deliveryHandler release];
    [super dealloc];
}

- (void)resetInMemoryDeduplication {
    @synchronized(_seenMessageIDs) {
        [_seenMessageIDs removeAllObjects];
    }
}

- (void)_markMessageDeliveredID:(NSData *)msgID expiresAt:(int64_t)expiresAt {
    if (![msgID length]) return;
    [[SGDatabaseManager sharedManager] markMessageIDAsSeen:msgID
                                                 expiresAt:expiresAt];
    @synchronized(_seenMessageIDs) {
        if (![_seenMessageIDs containsObject:msgID]) {
            [_seenMessageIDs addObject:msgID];
            if ([_seenMessageIDs count] > kSGSeenMessageIDCap) {
                [_seenMessageIDs removeObjectAtIndex:0];
            }
        }
    }
}

- (void)_finishMessageID:(NSData *)msgID
                ackStatus:(int)ackStatus
                expiresAt:(int64_t)expiresAt {
    SGP_EnqueueAcknowledgement(msgID, ackStatus);
    [self _markMessageDeliveredID:msgID expiresAt:expiresAt];
}

- (void)_advanceLastDeliveredSeqIfNeeded:(int64_t)arrivedSeq {
    if (arrivedSeq <= 0) return;
    SGDatabaseManager *db = [SGDatabaseManager sharedManager];
    int64_t currentMax = [db lastDeliveredSeq];
    if (arrivedSeq > currentMax) [db updateLastDeliveredSeq:arrivedSeq];
}

- (SGControlError)_deliverBundleID:(NSString *)bundleID
                           payload:(NSDictionary *)payload {
    if (!_deliveryHandler) return SGCERR_INTERNAL;
    return _deliveryHandler(bundleID, payload);
}

- (void)processNotification:(NSDictionary *)messageDict {
    @autoreleasepool {
        NSData *msgID = messageDict[@"msg_id"];
        if (!msgID || [msgID length] != SGP_MSG_ID_LEN) return;

        char msgHex[SGP_MSG_ID_LEN * 2 + 1];
        SGCopyMessageIDHex(msgID, msgHex, sizeof(msgHex));

        SGDatabaseManager *db = [SGDatabaseManager sharedManager];
        if ([db hasSeenMessageID:msgID]) {
            SGLOGD(SGNotificationProcessor, "code=%s msg=%s ack=success action=redeliver_ack_only",
                   SGND_DELIVERY_DUPLICATE, msgHex);
            SGP_EnqueueAcknowledgement(msgID, SGP_ACK_SUCCESS);
            return;
        }
        if ([db hasLocalPendingDeliveryForMessageID:msgID]) {
            SGLOGD(SGNotificationProcessor, "code=%s msg=%s action=ignore_pending_retry",
                   SGND_DELIVERY_LOCAL_PENDING_DUPLICATE, msgHex);
            return;
        }
        @synchronized(_seenMessageIDs) {
            if ([_seenMessageIDs containsObject:msgID]) {
                SGP_EnqueueAcknowledgement(msgID, SGP_ACK_SUCCESS);
                return;
            }
        }

        NSNumber *expiresAtNum = messageDict[@"expires_at"];
        int64_t expiresAt = expiresAtNum ? [expiresAtNum longLongValue] : 0;
        int64_t now = (int64_t)time(NULL);
        if (expiresAt > 0 && now > expiresAt) {
            SGLOGI(SGNotificationProcessor, "code=%s msg=%s age=%llds expires_at=%lld now=%lld ack=expired",
                   SGND_DELIVERY_EXPIRED, msgHex, now - expiresAt, expiresAt, now);
            [self _finishMessageID:msgID ackStatus:SGP_ACK_EXPIRED expiresAt:expiresAt];
            return;
        }

        NSData *routingKey = messageDict[@"routing_key"];
        NSDictionary *routingData = [db tokenDataForRoutingKey:routingKey];
        if (!routingData) {
            SGLOGW(SGNotificationProcessor, "code=%s msg=%s action=drop reason=routing_key_missing",
                   SGND_DELIVERY_ROUTING_MISSING, msgHex);
            return;
        }

        if ([db isMutedForRoutingKey:routingKey]) {
            SGLOGI(SGNotificationProcessor, "code=%s msg=%s bundle=%s ack=success action=suppress",
                   SGND_DELIVERY_MUTED, msgHex, [routingData[@"bundleID"] UTF8String]);
            [self _finishMessageID:msgID ackStatus:SGP_ACK_SUCCESS expiresAt:expiresAt];
            return;
        }

        NSData *payloadBytes = messageDict[@"data"];
        if (!payloadBytes) {
            SGLOGW(SGNotificationProcessor, "code=%s msg=%s ack=parse_failed action=drop",
                   SGND_DELIVERY_PAYLOAD_EMPTY, msgHex);
            [self _finishMessageID:msgID ackStatus:SGP_ACK_PARSE_FAILED expiresAt:expiresAt];
            return;
        }

        SGLOGI(SGNotificationProcessor, "code=%s msg=%s bundle=%s encrypted=%s bytes=%lu result=received",
               SGND_DELIVERY_RECEIVED, msgHex, [routingData[@"bundleID"] UTF8String],
               [messageDict[@"is_encrypted"] boolValue] ? "yes" : "no",
               (unsigned long)[payloadBytes length]);

        if ([messageDict[@"is_encrypted"] boolValue]) {
            SGLOGD(SGNotificationProcessor, "code=%s msg=%s bytes=%lu action=decrypt",
                   SGND_DELIVERY_PAYLOAD_ENCRYPTED, msgHex,
                   (unsigned long)[payloadBytes length]);
            if ([payloadBytes length] < SGP_GCM_TAG_LEN) {
                SGLOGW(SGNotificationProcessor, "code=%s msg=%s bytes=%lu min=%d ack=decrypt_failed action=drop",
                       SGND_DELIVERY_CIPHERTEXT_SHORT, msgHex,
                       (unsigned long)[payloadBytes length], SGP_GCM_TAG_LEN);
                [self _finishMessageID:msgID ackStatus:SGP_ACK_DECRYPT_FAILED expiresAt:expiresAt];
                return;
            }
            NSData *iv = messageDict[@"iv"];
            if (!iv) {
                SGLOGW(SGNotificationProcessor, "code=%s msg=%s ack=decrypt_failed action=drop",
                       SGND_DELIVERY_IV_MISSING, msgHex);
                [self _finishMessageID:msgID ackStatus:SGP_ACK_DECRYPT_FAILED expiresAt:expiresAt];
                return;
            }
            payloadBytes = SG_CryptoDecryptAESGCM(
                payloadBytes, routingData[@"e2eeKey"], iv, nil);
            if (!payloadBytes) {
                SGLOGE(SGNotificationProcessor, "code=%s msg=%s ack=decrypt_failed action=drop",
                       SGND_DELIVERY_DECRYPT_FAILED, msgHex);
                [self _finishMessageID:msgID ackStatus:SGP_ACK_DECRYPT_FAILED expiresAt:expiresAt];
                return;
            }
        } else {
            SGLOGD(SGNotificationProcessor, "code=%s msg=%s bytes=%lu",
                   SGND_DELIVERY_PAYLOAD_PLAINTEXT, msgHex,
                   (unsigned long)[payloadBytes length]);
        }

        if ([messageDict[@"is_compressed"] boolValue]) {
            NSData *inflated = SG_PayloadInflate(
                (const uint8_t *)[payloadBytes bytes],
                (uint32_t)[payloadBytes length], SGP_MAX_INFLATED_LEN);
            if (!inflated) {
                SGLOGW(SGNotificationProcessor, "code=%s msg=%s bytes=%lu ack=parse_failed action=drop",
                       SGND_DELIVERY_INFLATE_FAILED, msgHex,
                       (unsigned long)[payloadBytes length]);
                [self _finishMessageID:msgID ackStatus:SGP_ACK_PARSE_FAILED expiresAt:expiresAt];
                return;
            }
            SGLOGD(SGNotificationProcessor, "code=%s msg=%s in=%lu out=%lu action=inflate",
                   SGND_DELIVERY_PAYLOAD_INFLATED, msgHex,
                   (unsigned long)[payloadBytes length],
                   (unsigned long)[inflated length]);
            payloadBytes = inflated;
        }

        uint8_t contentType =
            (uint8_t)[messageDict[@"content_type"] unsignedCharValue];
        NSDictionary *parsed = SG_PayloadDecode(
            (const uint8_t *)[payloadBytes bytes],
            (uint32_t)[payloadBytes length], contentType);
        if (![parsed count]) {
            SGLOGW(SGNotificationProcessor, "code=%s msg=%s bytes=%lu fmt=%u ack=parse_failed action=drop",
                   SGND_DELIVERY_PARSE_FAILED, msgHex,
                   (unsigned long)[payloadBytes length], (unsigned)contentType);
            [self _finishMessageID:msgID ackStatus:SGP_ACK_PARSE_FAILED expiresAt:expiresAt];
            return;
        }

        NSNumber *seqNum = messageDict[@"device_seq"];
        int64_t arrivedSeq = seqNum ? [seqNum longLongValue] : 0;
        NSString *bundleID = routingData[@"bundleID"];
        SGLOGI(SGNotificationProcessor, "code=%s msg=%s bundle=%s keys=%lu action=deliver",
               SGND_DELIVERY_DISPATCHING, msgHex, [bundleID UTF8String],
               (unsigned long)[parsed count]);
        SGControlError deliveryKr = [self _deliverBundleID:bundleID payload:parsed];
        if (deliveryKr == SGCERR_OK) {
            [self _finishMessageID:msgID ackStatus:SGP_ACK_SUCCESS expiresAt:expiresAt];
            [self _advanceLastDeliveredSeqIfNeeded:arrivedSeq];
            [self kickPendingDeliveryDrain];
        } else {
            NSData *serialized = [NSPropertyListSerialization
                dataFromPropertyList:parsed
                              format:NSPropertyListBinaryFormat_v1_0
                    errorDescription:NULL];
            int64_t effective = (expiresAt > now)
                ? expiresAt : (now + kSGLocalPendingFallbackDeadlineSec);
            BOOL queued = serialized &&
                [db enqueueLocalPendingDeliveryForMessageID:msgID
                                                   bundleID:bundleID
                                                    payload:serialized
                                                  deviceSeq:arrivedSeq
                                                  expiresAt:effective];
            if (queued) {
                dispatch_async(_deliveryQueue, ^{ [self _startRetryTimer]; });
                SGLOGW(SGNotificationProcessor, "code=%s msg=%s bundle=%s kr=%d action=queue_local_retry",
                       SGND_DELIVERY_LOCAL_RETRY_QUEUED, msgHex,
                       [bundleID UTF8String], deliveryKr);
            } else if (!serialized) {
                SGLOGE(SGNotificationProcessor, "code=%s msg=%s kr=%d ack=parse_failed action=halt_resends",
                       SGND_DELIVERY_LOCAL_RETRY_BAD_PAYLOAD, msgHex, deliveryKr);
                [self _finishMessageID:msgID ackStatus:SGP_ACK_PARSE_FAILED expiresAt:expiresAt];
            } else {
                SGLOGE(SGNotificationProcessor, "code=%s msg=%s kr=%d action=abort_for_redelivery",
                       SGND_DELIVERY_LOCAL_RETRY_ENQUEUE_FAILED, msgHex, deliveryKr);
                SGP_AbortConnection();
            }
        }

    }
}

- (void)_startRetryTimer {
    if (_retryTimer) return;
    _retryTimer = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _deliveryQueue);
    dispatch_source_set_timer(
        _retryTimer,
        dispatch_time(DISPATCH_TIME_NOW,
                      kSGDrainSafetyIntervalSec * NSEC_PER_SEC),
        kSGDrainSafetyIntervalSec * NSEC_PER_SEC,
        kSGDrainSafetyLeewaySec * NSEC_PER_SEC);
    dispatch_source_set_event_handler(_retryTimer, ^{ [self _drainPending]; });
    dispatch_resume(_retryTimer);
}

- (void)_stopRetryTimer {
    if (!_retryTimer) return;
    dispatch_source_cancel(_retryTimer);
    dispatch_release(_retryTimer);
    _retryTimer = NULL;
}

- (void)kickPendingDeliveryDrain {
    dispatch_async(_deliveryQueue, ^{ [self _drainPending]; });
}

- (void)suspendPendingDeliveryRetries {
    if (!_deliveryQueue) return;
    dispatch_sync(_deliveryQueue, ^{ [self _stopRetryTimer]; });
}

- (void)_drainPending {
    @autoreleasepool {
        SGDatabaseManager *db = [SGDatabaseManager sharedManager];
        NSArray *pending = [db allLocalPendingDeliveries];
        if (![pending count]) {
            [self _stopRetryTimer];
            return;
        }
        [self _startRetryTimer];

        int64_t now = (int64_t)time(NULL);
        for (NSDictionary *entry in pending) {
            @autoreleasepool {
                NSData *msgID = entry[@"msgID"];
                NSString *bundleID = entry[@"bundleID"];
                NSData *serialized = entry[@"payload"];
                int64_t deviceSeq = [entry[@"deviceSeq"] longLongValue];
                int64_t expiresAt = [entry[@"expiresAt"] longLongValue];
                char msgHex[SGP_MSG_ID_LEN * 2 + 1];
                SGCopyMessageIDHex(msgID, msgHex, sizeof(msgHex));

                if (now > expiresAt) {
                    SGLOGW(SGNotificationProcessor, "code=%s msg=%s bundle=%s ack=expired action=remove",
                           SGND_DELIVERY_LOCAL_RETRY_EXPIRED, msgHex,
                           [bundleID UTF8String]);
                    [self _finishMessageID:msgID ackStatus:SGP_ACK_EXPIRED expiresAt:expiresAt];
                    [db removeLocalPendingDeliveryForMessageID:msgID];
                    continue;
                }

                NSDictionary *parsed = (NSDictionary *)[NSPropertyListSerialization
                    propertyListFromData:serialized
                        mutabilityOption:NSPropertyListImmutable
                                  format:NULL
                        errorDescription:NULL];
                if (![parsed isKindOfClass:[NSDictionary class]]) {
                    SGLOGE(SGNotificationProcessor, "code=%s msg=%s bundle=%s ack=parse_failed action=remove",
                           SGND_DELIVERY_LOCAL_RETRY_BAD_PAYLOAD, msgHex,
                           [bundleID UTF8String]);
                    [self _finishMessageID:msgID ackStatus:SGP_ACK_PARSE_FAILED expiresAt:expiresAt];
                    [db removeLocalPendingDeliveryForMessageID:msgID];
                    continue;
                }

                SGControlError kr = [self _deliverBundleID:bundleID payload:parsed];
                if (kr == SGCERR_OK) {
                    SGLOGI(SGNotificationProcessor, "code=%s msg=%s bundle=%s result=delivered",
                           SGND_DELIVERY_LOCAL_RETRY_SUCCEEDED, msgHex,
                           [bundleID UTF8String]);
                    [self _finishMessageID:msgID ackStatus:SGP_ACK_SUCCESS expiresAt:expiresAt];
                    [self _advanceLastDeliveredSeqIfNeeded:deviceSeq];
                    [db removeLocalPendingDeliveryForMessageID:msgID];
                }
            }
        }

        if (![[db allLocalPendingDeliveries] count]) [self _stopRetryTimer];
    }
}

@end
