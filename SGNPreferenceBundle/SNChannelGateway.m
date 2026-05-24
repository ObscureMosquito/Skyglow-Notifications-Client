#import "SNChannelGateway.h"
#import "../Skyglow-Notifications-Daemon/SGControlChannel.h"
#import "../Skyglow-Notifications-Daemon/SGControlChannelProtocol.h"
#include <string.h>

@implementation SNChannelGateway

/**
 * Persistent channels for the bundle's lifetime.  Constructed lazily on
 * first use of either side so a settings page that never touches Skyglow
 * (e.g. the user just opened Settings.app for an unrelated reason) costs
 * nothing.  Once allocated, the underlying SGControlChannel handles its
 * own reconnect / pending queue.
 */
static SGControlChannel *gDaemonClient = nil;
static SGControlChannel *gSpringBoardClient = nil;
static dispatch_once_t   gDaemonOnce;
static dispatch_once_t   gSpringBoardOnce;

static SGControlChannel *DaemonClient(void) {
    dispatch_once(&gDaemonOnce, ^{
        gDaemonClient = [SGControlChannel clientForServiceName:SKYGLOW_CONTROL_SERVICE_DAEMON];
        [gDaemonClient start];
    });
    return gDaemonClient;
}

static SGControlChannel *SpringBoardClient(void) {
    dispatch_once(&gSpringBoardOnce, ^{
        gSpringBoardClient = [SGControlChannel clientForServiceName:SKYGLOW_CONTROL_SERVICE_SPRINGBOARD];
        [gSpringBoardClient start];
    });
    return gSpringBoardClient;
}

+ (void)postReloadConfig {
    [DaemonClient() sendRequest:SGCMSG_RELOAD_CONFIG
                        payload:nil
                        timeout:0
                     completion:nil];
}

+ (void)postTestInject {
    [DaemonClient() sendRequest:SGCMSG_TEST_INJECT
                        payload:nil
                        timeout:0
                     completion:nil];
}

+ (void)postRegisterInputAppForBundleId:(NSString *)bundleId {
    if (bundleId.length == 0) return;
    SGCBundleIdPayload payload;
    memset(&payload, 0, sizeof(payload));
    strlcpy(payload.bundleID, [bundleId UTF8String], sizeof(payload.bundleID));
    [SpringBoardClient() sendRequest:SGCMSG_REGISTER_INPUT_APP
                             payload:[NSData dataWithBytes:&payload length:sizeof(payload)]
                             timeout:0
                          completion:nil];
}

+ (void)postUnregisterInputAppForBundleId:(NSString *)bundleId {
    if (bundleId.length == 0) return;
    SGCBundleIdPayload payload;
    memset(&payload, 0, sizeof(payload));
    strlcpy(payload.bundleID, [bundleId UTF8String], sizeof(payload.bundleID));
    [SpringBoardClient() sendRequest:SGCMSG_UNREGISTER_INPUT_APP
                             payload:[NSData dataWithBytes:&payload length:sizeof(payload)]
                             timeout:0
                          completion:nil];
}

@end
