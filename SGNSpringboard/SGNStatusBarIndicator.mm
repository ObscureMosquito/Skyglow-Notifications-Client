#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import "LSStatusBarItem.h"
#import "../Skyglow-Notifications-Daemon/SGStatusServer.h"
#import "../Skyglow-Notifications-Daemon/SGSharedConstants.h"
#import "../Skyglow-Notifications-Daemon/SGControlChannel.h"
#import "../Skyglow-Notifications-Daemon/SGControlChannelProtocol.h"
#import "../Skyglow-Notifications-Daemon/SGLog.h"

static NSString * const kStatusBarIndicatorEnabledKey = @"statusBarIndicatorEnabled";
static NSString * const kIndicatorIdentifier          = @"com.skyglow.snd.indicator";
static NSString * const kIndicatorViewClassName       = @"SGNIndicatorItemView";

#pragma mark - Color mapping

static UIColor *SGNColorForState(SGState state) {
    switch (state) {
        case SGStateConnected:
            return [UIColor colorWithRed:0.2f green:0.7f blue:0.2f alpha:1.0f];
        case SGStateConnecting:
        case SGStateAuthenticating:
        case SGStateResolvingDNS:
        case SGStateBackingOff:
        case SGStateRegistering:
            return [UIColor orangeColor];
        case SGStateIdleNoNetwork:
        case SGStateIdleCircuitOpen:
        case SGStateIdleDNSFailed:
            return [UIColor colorWithRed:0.9f green:0.6f blue:0.1f alpha:1.0f];
        case SGStateErrorAuth:
        case SGStateErrorBadConfig:
        case SGStateErrorVersionMismatch:
        case SGStateError:
            return [UIColor colorWithRed:0.85f green:0.2f blue:0.2f alpha:1.0f];
        default:
            return [UIColor grayColor];
    }
}

#pragma mark - Custom view (registered dynamically)

/* libstatusbar's UIStatusBarCustomItemView class is created at runtime via
 * objc_allocateClassPair, so there's no compile-time symbol to inherit from
 * statically.  We mirror the same pattern: register a UIStatusBarCustomItemView
 * subclass after libstatusbar has set up its base class, override
 * contentsImageForStyle: to draw a coloured circle, and reference it from
 * the LSStatusBarItem by name. */

static UIColor *gIndicatorColor = nil;

static UIImage *SGNIndicator_DrawCircle(id self, SEL _cmd, int style) {
    (void)self; (void)_cmd; (void)style;
    CGFloat side = 12.0f;
    CGSize size = CGSizeMake(side, side);
    UIGraphicsBeginImageContextWithOptions(size, NO, 0.0f);
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    UIColor *c = gIndicatorColor ?: [UIColor grayColor];
    CGContextSetFillColorWithColor(ctx, c.CGColor);
    CGContextFillEllipseInRect(ctx, CGRectMake(1.0f, 1.0f, side - 2.0f, side - 2.0f));
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return img;
}

static void SGNIndicator_RegisterViewClassIfNeeded(void) {
    if (NSClassFromString(kIndicatorViewClassName)) {
        SGLOGI(SGNStatusBar, "view class already registered");
        return;
    }
    Class super = NSClassFromString(@"UIStatusBarCustomItemView");
    if (!super) {
        SGLOGE(SGNStatusBar, "UIStatusBarCustomItemView superclass not found — libstatusbar not loaded?");
        return;
    }
    Class mine = objc_allocateClassPair(super,
        [kIndicatorViewClassName UTF8String], 0);
    if (!mine) {
        SGLOGE(SGNStatusBar, "objc_allocateClassPair returned NULL");
        return;
    }
    class_addMethod(mine,
                    @selector(contentsImageForStyle:),
                    (IMP)SGNIndicator_DrawCircle,
                    "@@:i");
    objc_registerClassPair(mine);
    SGLOGI(SGNStatusBar, "view class registered as subclass of UIStatusBarCustomItemView");
}

#pragma mark - Lifecycle

static LSStatusBarItem *gIndicatorItem = nil;

static BOOL SGNIndicatorPrefEnabled(void) {
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:SG_PREFS_PLIST_PATH];
    NSNumber *v = [prefs objectForKey:kStatusBarIndicatorEnabledKey];
    BOOL enabled = v ? [v boolValue] : NO;
    SGLOGI(SGNStatusBar, "pref read: path=%s prefs_present=%d enabled=%d",
           [SG_PREFS_PLIST_PATH UTF8String], prefs != nil, enabled);
    return enabled;
}

static void SGNIndicatorApplyState(SGState state) {
    UIColor *next = SGNColorForState(state);
    if ([gIndicatorColor isEqual:next]) return;
    [gIndicatorColor release];
    gIndicatorColor = [next retain];
    [gIndicatorItem update];
}

static void SGNIndicatorEnsureCreated(void) {
    if (gIndicatorItem) {
        SGLOGI(SGNStatusBar, "ensureCreated: already present, skip");
        return;
    }
    SGNIndicator_RegisterViewClassIfNeeded();
    gIndicatorItem = [[LSStatusBarItem alloc]
        initWithIdentifier:kIndicatorIdentifier
                 alignment:StatusBarAlignmentRight];
    if (!gIndicatorItem) {
        SGLOGE(SGNStatusBar, "LSStatusBarItem alloc returned nil");
        return;
    }
    [gIndicatorItem setCustomViewClass:kIndicatorViewClassName];
    [gIndicatorItem setVisible:YES];
    SGLOGI(SGNStatusBar, "indicator item created and visible");
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

extern "C" void SGNStatusBarIndicator_Start(SGControlChannel *daemonClient) {
    SGLOGI(SGNStatusBar, "Start: daemonClient=%p", daemonClient);
    SGNIndicatorReconcileWithPref();

    if (!daemonClient) {
        SGLOGE(SGNStatusBar, "Start: daemonClient is NULL — no live updates");
        return;
    }

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
