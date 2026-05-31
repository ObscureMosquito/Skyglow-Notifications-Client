#import <UIKit/UIKit.h>
#import "LSStatusBarItem.h"
#import "../Skyglow-Notifications-Daemon/SGStatusServer.h"
#import "../Skyglow-Notifications-Daemon/SGSharedConstants.h"
#import "../Skyglow-Notifications-Daemon/SGControlChannel.h"
#import "../Skyglow-Notifications-Daemon/SGControlChannelProtocol.h"
#import "../Skyglow-Notifications-Daemon/SGLog.h"

static NSString * const kStatusBarIndicatorEnabledKey = @"statusBarIndicatorEnabled";
static NSString * const kIndicatorIdentifier          = @"com.skyglow.snd.indicator";

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
        case SGStateIdleDNSFailed:
        case SGStateIdleNoNetwork:
        case SGStateIdleCircuitOpen:
        case SGStateErrorAuth:
        case SGStateErrorBadConfig:
        case SGStateErrorVersionMismatch:
        case SGStateError:
            return @"sgn_error";
        case SGStateStarting:
        case SGStateDisabled:
        case SGStateIdleUnregistered:
        case SGStateShuttingDown:
        default:
            return @"sgn_off";
    }
}

#pragma mark - Lifecycle

static LSStatusBarItem *gIndicatorItem = nil;
static NSString        *gIndicatorImageName = nil;

static BOOL SGNIndicatorPrefEnabled(void) {
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:SG_PREFS_PLIST_PATH];
    NSNumber *v = [prefs objectForKey:kStatusBarIndicatorEnabledKey];
    BOOL enabled = v ? [v boolValue] : NO;
    SGLOGI(SGNStatusBar, "pref read: path=%s prefs_present=%d enabled=%d",
           [SG_PREFS_PLIST_PATH UTF8String], prefs != nil, enabled);
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

    [daemonClient subscribeToEvent:SGCEVT_CONFIG_RELOADED
                           handler:^(SGControlEventType eventType, NSData *data) {
        SGLOGI(SGNStatusBar, "CONFIG_RELOADED received — reconciling pref");
        SGNIndicatorReconcileWithPref();
    } completion:^(SGControlError err, uint64_t subId) {
        SGLOGI(SGNStatusBar, "CONFIG_RELOADED subscribe completion: err=%d subId=%llu", err, subId);
    }];
}

extern "C" void SGNStatusBarIndicator_Start(SGControlChannel *daemonClient) {
    SGLOGI(SGNStatusBar, "Start: daemonClient=%p", daemonClient);
    SGNIndicatorReconcileWithPref();

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
