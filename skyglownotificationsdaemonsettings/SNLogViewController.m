#import "SNLogViewController.h"
#import "SNDataManager.h"
#include <Foundation/Foundation.h>
#include <QuartzCore/QuartzCore.h>

@interface SNLogViewController ()
@property (nonatomic, strong) UILabel     *logLabel;
@property (nonatomic, strong) UIImageView *overlayView;
@end

@implementation SNLogViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    self.view.backgroundColor = [UIColor clearColor];

    self.logLabel = [[UILabel alloc] initWithFrame:self.view.bounds];
    self.logLabel.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.logLabel.textAlignment   = NSTextAlignmentCenter;
    self.logLabel.layer.cornerRadius = 7.0;
    self.logLabel.clipsToBounds   = YES;
    self.logLabel.backgroundColor = [UIColor blackColor];
    self.logLabel.textColor       = [UIColor whiteColor];
    self.logLabel.font            = [UIFont boldSystemFontOfSize:13.0];
    [self.view addSubview:self.logLabel];

    NSString *imagePath = @"/Library/PreferenceBundles/SkyglowNotificationsDaemonSettings.bundle/Overlay-Gloss.png";
    UIImage *glossImage = [UIImage imageWithContentsOfFile:imagePath];
    if (glossImage) {
        self.overlayView = [[UIImageView alloc] initWithImage:glossImage];
        self.overlayView.frame = self.logLabel.bounds;
        self.overlayView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        self.overlayView.alpha = 0.6;
        self.overlayView.contentMode = UIViewContentModeScaleToFill;
        [self.logLabel addSubview:self.overlayView];
    }

    // Listen for UI-to-UI refresh events. The daemon itself never posts this;
    // it is posted by settings UI actions (register, unregister, etc.) so the
    // status badge refreshes immediately after those actions complete.
    CFNotificationCenterAddObserver(
        CFNotificationCenterGetDarwinNotifyCenter(),
        (__bridge const void *)(self),
        &daemonStatusStatusUpdate,
        CFSTR(kDaemonStatusNewStatus),
        NULL,
        CFNotificationSuspensionBehaviorDeliverImmediately);

    [self updateLogWithStatus];
}

- (void)dealloc {
    CFNotificationCenterRemoveObserver(
        CFNotificationCenterGetDarwinNotifyCenter(),
        (__bridge const void *)(self),
        CFSTR(kDaemonStatusNewStatus),
        NULL);
    NSLog(@"SNLogViewController: Observers removed.");
}

void daemonStatusStatusUpdate(CFNotificationCenterRef center,
                              void *observer,
                              CFStringRef name,
                              const void *object,
                              CFDictionaryRef userInfo) {
    SNLogViewController *vc = (__bridge SNLogViewController *)observer;
    dispatch_async(dispatch_get_main_queue(), ^{
        [vc updateLogWithStatus];
    });
}

- (void)updateLogWithStatus {
    // Query the daemon over the Unix domain socket instead of reading
    // the stale status plist (which the daemon no longer writes).
    SGStatusPayload payload = [[SNDataManager shared] queryDaemonStatus];
    SGState state = (SGState)payload.state;

    NSString *message;
    UIColor  *background;
    CGFloat   alpha = 0.5;

    switch (state) {
        case SGStateConnected:
            background = [UIColor colorWithRed:0.2 green:0.7 blue:0.2 alpha:1.0];
            message = @"Connected and receiving notifications.";
            break;

        case SGStateAuthenticating:
            background = [UIColor orangeColor];
            message = @"Connected. Authenticating…";
            break;

        case SGStateConnecting:
            background = [UIColor colorWithRed:1.0 green:0.75 blue:0.0 alpha:1.0];
            message = @"Connecting…";
            break;

        case SGStateBackingOff: {
            background = [UIColor orangeColor];
            uint32_t sec = payload.currentBackoffSec;
            if (sec > 0)
                message = [NSString stringWithFormat:@"Reconnecting in %us…", sec];
            else
                message = @"Reconnecting…";
            break;
        }

        case SGStateResolvingDNS:
            background = [UIColor colorWithRed:1.0 green:0.75 blue:0.0 alpha:1.0];
            message = @"Resolving server address…";
            break;

        case SGStateIdleDNSFailed:
            background = [UIColor colorWithRed:0.85 green:0.2 blue:0.2 alpha:1.0];
            message = @"DNS lookup failed. Check server address.";
            break;

        case SGStateIdleNoNetwork:
            background = [UIColor colorWithRed:0.9 green:0.6 blue:0.1 alpha:1.0];
            message = @"No network. Waiting for connectivity…";
            break;

        case SGStateIdleCircuitOpen: {
            background = [UIColor colorWithRed:0.85 green:0.2 blue:0.2 alpha:1.0];
            uint32_t f = payload.consecutiveFailures;
            message = [NSString stringWithFormat:@"Paused after %u failures. Will retry.", f];
            break;
        }

        case SGStateDisabled:
            background = [UIColor grayColor];
            message = @"The daemon is currently disabled.";
            break;

        case SGStateIdleUnregistered:
            background = [UIColor orangeColor];
            message = @"Not registered. Enter a server address to begin.";
            break;

        case SGStateErrorAuth:
            background = [UIColor colorWithRed:0.85 green:0.2 blue:0.2 alpha:1.0];
            message = @"Authentication failed. Try re-registering.";
            break;

        case SGStateErrorBadConfig:
            background = [UIColor colorWithRed:0.55 green:0.0 blue:0.55 alpha:1.0];
            message = @"Bad server configuration. Check settings.";
            break;

        case SGStateError:
            background = [UIColor colorWithRed:0.85 green:0.2 blue:0.2 alpha:1.0];
            message = @"An error occurred. Please check the daemon.";
            break;

        case SGStateStarting:
            // Either the daemon just started or the socket isn't up yet.
            background = [UIColor darkGrayColor];
            message = @"Starting…";
            break;

        case SGStateShuttingDown:
            background = [UIColor darkGrayColor];
            message = @"Shutting down…";
            break;

        default:
            background = [UIColor darkGrayColor];
            message = @"Unknown status.";
            break;
    }

    self.logLabel.backgroundColor = [background colorWithAlphaComponent:alpha];
    self.logLabel.text = message;
}

- (UIColor *)scanlinePattern {
    UIGraphicsBeginImageContextWithOptions(CGSizeMake(1, 2), NO, 0.0);
    CGContextRef context = UIGraphicsGetCurrentContext();
    [[UIColor clearColor] setFill];
    CGContextFillRect(context, CGRectMake(0, 0, 1, 1));
    [[UIColor colorWithWhite:0.0 alpha:0.3] setFill];
    CGContextFillRect(context, CGRectMake(0, 1, 1, 1));
    UIImage *image = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return [UIColor colorWithPatternImage:image];
}

@end