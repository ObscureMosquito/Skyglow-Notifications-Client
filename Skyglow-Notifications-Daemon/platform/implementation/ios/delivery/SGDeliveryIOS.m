#import "SGDeliveryIOS.h"

#import "SGControlChannel.h"
#import "SGControlChannelProtocol.h"
#import "SGIOSPlatformService.h"
#import "SGLog.h"
#import "SGLogDiagnostics.h"
#import <libkern/OSAtomic.h>
#import <stddef.h>

@implementation SGDeliveryIOS {
    SGControlChannel *_channel;
}

- (id)init {
    if ((self = [super init])) {
        _channel = [[SGControlChannel clientForServiceName:
            SKYGLOW_CONTROL_SERVICE_SPRINGBOARD] retain];
    }
    return self;
}

- (void)setDeliveryReadyHandler:(void (^)(void))handler {
    void (^handlerCopy)(void) = [[handler copy] autorelease];
    [_channel setConnectionHandler:^(BOOL connected) {
        if (connected && handlerCopy) handlerCopy();
    }];
}

- (BOOL)start {
    return [_channel start];
}

- (void)stop {
    [_channel stop];
}

- (void)dealloc {
    [self stop];
    [_channel release];
    [super dealloc];
}

- (SGControlError)sendNotificationForBundleID:(NSString *)topic payload:(NSDictionary *)payload {
    if (!topic || [topic length] == 0) return SGCERR_INVALID_REQUEST;
    if (!_channel) {
        SGLOGW(SGDaemon, "code=%s bundle=%s result=unavailable", SGND_DELIVERY_SPRINGBOARD_UNAVAILABLE,
                    [topic length] ? [topic UTF8String] : "none");
        return SGCERR_UNREACHABLE;
    }

    NSData *plistData = payload
        ? [NSPropertyListSerialization dataWithPropertyList:payload
                                                     format:NSPropertyListBinaryFormat_v1_0
                                                    options:0 error:NULL]
        : nil;
    if (!plistData) plistData = [NSData data];
    if ([plistData length] > SG_CONTROL_MAX_USERINFO_SIZE) {
        SGLOGE(SGDaemon, "code=%s bundle=%s bytes=%lu max=%d result=failed", SGND_DELIVERY_PAYLOAD_TOO_LARGE,
                    [topic UTF8String], (unsigned long)[plistData length], SG_CONTROL_MAX_USERINFO_SIZE);
        return SGCERR_INVALID_REQUEST;
    }

    SGCPushDeliveryPayload pd;
    memset(&pd, 0, sizeof(pd));
    strlcpy(pd.bundleID, [topic UTF8String], sizeof(pd.bundleID));
    pd.userInfoLength = (uint32_t)[plistData length];
    if (pd.userInfoLength > 0) memcpy(pd.userInfoData, [plistData bytes], pd.userInfoLength);
    NSUInteger sendLen = offsetof(SGCPushDeliveryPayload, userInfoData) + pd.userInfoLength;

    __block int32_t result = (int32_t)SGCERR_INTERNAL;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);

    dispatch_retain(sema);
    [_channel sendRequest:SGCMSG_PUSH_DELIVERY
                  payload:[NSData dataWithBytes:&pd length:sendLen]
                  timeout:0
               completion:^(SGControlError err, const SGControlChannelMessage *response) {
        if (err == SGCERR_OK)
            OSAtomicCompareAndSwap32Barrier((int32_t)SGCERR_INTERNAL, (int32_t)SGCERR_OK, &result);
        dispatch_semaphore_signal(sema);
        dispatch_release(sema);
    }];
    int64_t waitNs = (int64_t)((SG_CONTROL_DEFAULT_REQUEST_TIMEOUT_SEC + 1.0) * NSEC_PER_SEC);
    long waited = dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, waitNs));
    SGControlError kr = (waited == 0) ? (SGControlError)OSAtomicAdd32Barrier(0, &result) : SGCERR_TIMEOUT;
    dispatch_release(sema);
    return kr;
}

#pragma mark - Registration ops (proxied to the SpringBoard tweak)

- (void)sendNativeBundleRequest:(SGControlMessageType)messageType
                       bundleID:(NSString *)bundleID
                     completion:(void (^)(SGControlError,
                                           NSString *))completion {
    if (![bundleID length]) {
        if (completion) completion(SGCERR_INVALID_REQUEST, @"bundle id required");
        return;
    }
    if (!_channel) {
        if (completion) completion(SGCERR_UNREACHABLE, nil);
        return;
    }

    SGCBundleIdPayload payload;
    memset(&payload, 0, sizeof(payload));
    strlcpy(payload.bundleID, [bundleID UTF8String],
            sizeof(payload.bundleID));
    [_channel sendRequest:messageType
                  payload:[NSData dataWithBytes:&payload length:sizeof(payload)]
                  timeout:0
               completion:^(SGControlError err, const SGControlChannelMessage *r) {
        NSString *detail = nil;
        if (err != SGCERR_OK && r &&
            r->messageType == SGCMSG_ERROR_RESPONSE &&
            r->payloadLength >= sizeof(SGCErrorResponsePayload)) {
            const SGCErrorResponsePayload *errorPayload =
                (const SGCErrorResponsePayload *)r->payload;
            detail = [[[NSString alloc]
                initWithBytes:errorPayload->message
                       length:strnlen(errorPayload->message,
                                      sizeof(errorPayload->message))
                     encoding:NSUTF8StringEncoding] autorelease];
        }
        if (completion) completion(err, detail);
    }];
}

- (void)resetAppRegistrationForBundleID:(NSString *)bundleID
                             completion:(void (^)(SGControlError,
                                                  NSString *))completion {
    [self sendNativeBundleRequest:SGCMSG_RESET_APP_REGISTRATION
                         bundleID:bundleID
                       completion:^(SGControlError err, NSString *detail) {
        if (err != SGCERR_OK && ![detail length]) {
            detail = (err == SGCERR_TIMEOUT || err == SGCERR_UNREACHABLE)
                ? @"SpringBoard did not respond"
                : @"SpringBoard rejected the reset request";
        }
        if (completion) completion(err, detail);
    }];
}

- (void)listNativePushAppsWithCompletion:(void (^)(SGControlError, NSData *))completion {
    if (!_channel) { if (completion) completion(SGCERR_UNREACHABLE, nil); return; }
    [_channel sendRequest:SGCMSG_LIST_NATIVE_PUSH_APPS
                  payload:nil
                  timeout:0
               completion:^(SGControlError err, const SGControlChannelMessage *r) {
        if (err == SGCERR_OK && r) {
            if (completion) completion(SGCERR_OK, [NSData dataWithBytes:r->payload length:r->payloadLength]);
        } else if (completion) {
            completion(err, nil);
        }
    }];
}

- (void)registerNativePushAppForBundleID:(NSString *)bundleID
                              completion:(void (^)(SGControlError,
                                                   NSString *))completion {
    [self sendNativeBundleRequest:SGCMSG_REGISTER_NATIVE_PUSH_APP
                         bundleID:bundleID completion:completion];
}

- (void)requestNativeNotificationAuthorizationForBundleID:(NSString *)bundleID
    completion:(void (^)(SGControlError, NSString *))completion {
    [self sendNativeBundleRequest:SGCMSG_AUTHORIZE_NATIVE_PUSH_APP
                         bundleID:bundleID completion:completion];
}

- (void)registerInputAppForBundleID:(NSString *)bundleID
                         completion:(void (^)(SGControlError, NSString *))completion {
    [self sendNativeBundleRequest:SGCMSG_REGISTER_INPUT_APP
                         bundleID:bundleID completion:completion];
}

@end
