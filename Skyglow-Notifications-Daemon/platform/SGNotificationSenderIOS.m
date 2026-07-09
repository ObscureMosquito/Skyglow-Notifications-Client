#import "SGNotificationSender.h"

#if !TARGET_OS_OSX

#import "SGControlChannel.h"
#import "SGControlChannelProtocol.h"
#import "SGLog.h"
#import "SGLogDiagnostics.h"
#import <libkern/OSAtomic.h>
#import <stddef.h>

@implementation SGNotificationSender {
    SGControlChannel *_channel;
}

- (instancetype)initWithSpringBoardChannel:(SGControlChannel *)channel {
    if ((self = [super init])) _channel = [channel retain];
    return self;
}

- (void)dealloc { [_channel release]; [super dealloc]; }

- (kern_return_t)sendNotificationForBundleID:(NSString *)topic payload:(NSDictionary *)payload {
    if (!topic || [topic length] == 0) return KERN_INVALID_ARGUMENT;
    if (!_channel) {
        SGLOGW(SGDaemon, "code=%s bundle=%s result=unavailable", SGND_DELIVERY_SPRINGBOARD_UNAVAILABLE,
                    [topic length] ? [topic UTF8String] : "none");
        return KERN_FAILURE;
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
        return KERN_RESOURCE_SHORTAGE;
    }

    SGCPushDeliveryPayload pd;
    memset(&pd, 0, sizeof(pd));
    strlcpy(pd.bundleID, [topic UTF8String], sizeof(pd.bundleID));
    pd.userInfoLength = (uint32_t)[plistData length];
    if (pd.userInfoLength > 0) memcpy(pd.userInfoData, [plistData bytes], pd.userInfoLength);
    NSUInteger sendLen = offsetof(SGCPushDeliveryPayload, userInfoData) + pd.userInfoLength;

    __block int32_t result = (int32_t)KERN_FAILURE;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);

    dispatch_retain(sema);
    [_channel sendRequest:SGCMSG_PUSH_DELIVERY
                  payload:[NSData dataWithBytes:&pd length:sendLen]
                  timeout:0
               completion:^(SGControlError err, const SGControlChannelMessage *response) {
        if (err == SGCERR_OK)
            OSAtomicCompareAndSwap32Barrier((int32_t)KERN_FAILURE, (int32_t)KERN_SUCCESS, &result);
        dispatch_semaphore_signal(sema);
        dispatch_release(sema);
    }];
    int64_t waitNs = (int64_t)((SG_CONTROL_DEFAULT_REQUEST_TIMEOUT_SEC + 1.0) * NSEC_PER_SEC);
    long waited = dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, waitNs));
    kern_return_t kr = (waited == 0) ? (kern_return_t)OSAtomicAdd32Barrier(0, &result) : KERN_FAILURE;
    dispatch_release(sema);
    return kr;
}

@end

#endif  // !TARGET_OS_OSX
