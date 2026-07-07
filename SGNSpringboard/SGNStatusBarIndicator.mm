#import <UIKit/UIKit.h>
#import "LSStatusBarItem.h"
#import "SGStatusServer.h"
#import "SGSharedConstants.h"
#import "SGControlChannel.h"
#import "SGControlChannelProtocol.h"
#import "SGLog.h"
#include <notify.h>

static NSString * const kSGNIndicatorPlist   = @"/var/mobile/Library/Preferences/com.skyglow.sndp.indicator.plist";
static NSString * const kSGNIndicatorKey     = @"enabled";
static const char * const kSGNIndicatorNote  = "com.skyglow.sndp.indicator.changed";
static NSString * const kIndicatorIdentifier = @"com.skyglow.snd.indicator";

static NSString *SGNIndicatorPath(NSString *path) {
    static int rootless = -1;
    if (rootless < 0) {
        rootless = [[NSFileManager defaultManager]
            fileExistsAtPath:@"/var/jb"] ? 1 : 0;
    }
    return rootless ? [@"/var/jb" stringByAppendingString:path] : path;
}

#pragma mark - State → image name mapping

static NSString *SGNImageNameForState(SGState state) {
    switch (state) {
        case SGStateConnected:
            return @"sgn_connected";
        case SGStateResolvingDNS:
        case SGStateConnecting:
        case SGStateAuthenticating:
        case SGStateBackingOff:
        case SGStateRegistering:
            return @"sgn_connecting";
        case SGStateIdleNoNetwork:
        case SGStateIdleCircuitOpen:
        case SGStateErrorAuth:
        case SGStateErrorBadConfig:
        case SGStateErrorVersionMismatch:
            return @"sgn_error";
        case SGStateStarting:
        case SGStateDisabled:
        case SGStateIdleUnregistered:
        default:
            return @"sgn_off";
    }
}

#pragma mark - Lifecycle

static LSStatusBarItem *gIndicatorItem = nil;
static NSString        *gIndicatorImageName = nil;

static BOOL SGNIndicatorPrefEnabled(void) {
    NSNumber *v = [[NSDictionary dictionaryWithContentsOfFile:
                       SGNIndicatorPath(kSGNIndicatorPlist)]
                      objectForKey:kSGNIndicatorKey];
    BOOL enabled = v ? [v boolValue] : NO;
    SGLOGI(SGNStatusBar, "pref read: enabled=%d value_present=%d", enabled, v != nil);
    return enabled;
}

static void SGNIndicatorApplyState(SGState state) {
    NSString *next = SGNImageNameForState(state);
    if ([gIndicatorImageName isEqualToString:next]) return;
    [gIndicatorImageName release];
    gIndicatorImageName = [next retain];
    if (gIndicatorItem) gIndicatorItem.imageName = gIndicatorImageName;
}

static void SGNIndicatorEnsureCreated(void) {
    if (gIndicatorItem) {
        SGLOGI(SGNStatusBar, "ensureCreated: already present, skip");
        return;
    }
    gIndicatorItem = [[LSStatusBarItem alloc]
        initWithIdentifier:kIndicatorIdentifier
                 alignment:StatusBarAlignmentRight];
    if (!gIndicatorItem) {
        SGLOGE(SGNStatusBar, "LSStatusBarItem alloc returned nil");
        return;
    }
    gIndicatorItem.imageName = gIndicatorImageName ?: @"sgn_off";
    [gIndicatorItem setVisible:YES];
    SGLOGI(SGNStatusBar, "indicator item created and visible (image=%s)",
           [(gIndicatorImageName ?: @"sgn_off") UTF8String]);
}

static void SGNIndicatorTearDown(void) {
    if (!gIndicatorItem) return;
    [gIndicatorItem setVisible:NO];
    [gIndicatorItem release];
    gIndicatorItem = nil;
    SGLOGI(SGNStatusBar, "indicator item torn down");
}

static void SGNIndicatorReconcileWithPref(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (SGNIndicatorPrefEnabled()) SGNIndicatorEnsureCreated();
        else                           SGNIndicatorTearDown();
    });
}

#pragma mark - Entry point

static void SGNSubscribeToDaemonEvents(SGControlChannel *daemonClient) {
    [daemonClient subscribeToEvent:SGCEVT_STATE_CHANGED
                           handler:^(SGControlEventType eventType, NSData *data) {
        SGLOGI(SGNStatusBar, "STATE_CHANGED received bytes=%lu", (unsigned long)[data length]);
        if ([data length] < sizeof(SGStatusPayload)) return;
        SGStatusPayload payload;
        memcpy(&payload, [data bytes], sizeof(payload));
        dispatch_async(dispatch_get_main_queue(), ^{
            SGNIndicatorApplyState((SGState)payload.state);
        });
    } completion:^(SGControlError err, uint64_t subId) {
        SGLOGI(SGNStatusBar, "STATE_CHANGED subscribe completion: err=%d subId=%llu", err, subId);
    }];
}

static void SGNRegisterIndicatorPrefObserver(void) {
    static BOOL registered = NO;
    if (registered) return;
    registered = YES;

    int token = 0;
    uint32_t rc = notify_register_dispatch(kSGNIndicatorNote,
                                           &token, dispatch_get_main_queue(),
                                           ^(int t) {
        SGNIndicatorReconcileWithPref();
    });
    if (rc != NOTIFY_STATUS_OK) {
        SGLOGE(SGNStatusBar, "notify_register_dispatch failed rc=%u", (unsigned)rc);
        registered = NO;
    }
}

extern "C" void SGNStatusBarIndicator_Start(SGControlChannel *daemonClient) {
    SGLOGI(SGNStatusBar, "Start: daemonClient=%p", daemonClient);
    SGNIndicatorReconcileWithPref();
    SGNRegisterIndicatorPrefObserver();

    if (!daemonClient) {
        SGLOGE(SGNStatusBar, "Start: daemonClient is NULL — no live updates");
        return;
    }

    SGNSubscribeToDaemonEvents(daemonClient);

    [daemonClient setConnectionHandler:^(BOOL connected) {
        if (!connected) return;
        SGLOGI(SGNStatusBar, "daemon (re)connected — re-subscribing + reconciling");
        SGNSubscribeToDaemonEvents(daemonClient);
        SGNIndicatorReconcileWithPref();
    }];
}
