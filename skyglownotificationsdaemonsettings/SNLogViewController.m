#import "SNLogViewController.h"
#include <Foundation/Foundation.h>
#include <QuartzCore/QuartzCore.h> // Needed for cornerRadius

@interface SNLogViewController ()
@property (nonatomic, strong) UILabel *logLabel;
@property (nonatomic, strong) UIImageView *overlayView;
@end

@implementation SNLogViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    self.view.backgroundColor = [UIColor clearColor];

    CGRect labelFrame = CGRectInset(self.view.bounds, 0.0, 0.0);

    self.logLabel = [[UILabel alloc] initWithFrame:labelFrame];
    self.logLabel.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.logLabel.textAlignment = NSTextAlignmentCenter; // Horizontal Center
    self.logLabel.layer.cornerRadius = 7.0;
    self.logLabel.clipsToBounds = YES;
    self.logLabel.backgroundColor = [UIColor blackColor];
    self.logLabel.textColor = [UIColor blackColor];
    self.logLabel.font = [UIFont boldSystemFontOfSize:13.0];

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

    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                    (__bridge const void *)(self),
                                    &daemonStatusStatusUpdate,
                                    CFSTR(kDaemonStatusNewStatus),
                                    NULL,
                                    CFNotificationSuspensionBehaviorDeliverImmediately);

    [self updateLogWithStatus];
}

- (void)dealloc {
    // Remove observers
    CFNotificationCenterRemoveObserver(CFNotificationCenterGetDarwinNotifyCenter(),
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
    SNLogViewController *self = (__bridge SNLogViewController *)observer;
    NSLog(@"SNLogViewController: Update Status notification received.");
    dispatch_async(dispatch_get_main_queue(), ^{
        [self updateLogWithStatus];
    });
}

- (void)updateLogWithStatus {
    NSString *path = @"/var/mobile/Library/Preferences/com.skyglow.sndp.status.plist";
    NSDictionary *statusDict = [NSDictionary dictionaryWithContentsOfFile:path];

    NSString *currentStatus = statusDict[@"currentStatus"];
    NSLog(@"SNLogViewController: Updating log with status: %@", currentStatus);

    NSString *userFriendlyMessage;
    UIColor *backgroundColor;
    CGFloat alpha = 0.5;

    if ([currentStatus isEqualToString:@"Disabled"]) {
        backgroundColor = [UIColor grayColor];
        userFriendlyMessage = @"The daemon is currently disabled.";
    } else if ([currentStatus isEqualToString:@"Error"]) {
        backgroundColor = [UIColor redColor];
        userFriendlyMessage = @"An error has occurred. Please check the daemon.";
    } else if ([currentStatus isEqualToString:@"ErrorInAuth"]) {
        backgroundColor = [UIColor redColor];
        userFriendlyMessage = @"Authentication failed. Try re-registering.";
    } else if ([currentStatus isEqualToString:@"EnabledNotConnected"]) {
        backgroundColor = [UIColor yellowColor];
        userFriendlyMessage = @"The daemon is enabled but not connected.";
    } else if ([currentStatus isEqualToString:@"EnabledNotRegistered"]) {
        backgroundColor = [UIColor orangeColor];
        userFriendlyMessage = @"Not registered. Enter a server address to begin.";
    } else if ([currentStatus isEqualToString:@"ConnectedNotAuthenticated"]) {
        backgroundColor = [UIColor orangeColor];
        userFriendlyMessage = @"Connected. Authenticatingâ¦";
    } else if ([currentStatus isEqualToString:@"Connected"]) {
        backgroundColor = [UIColor greenColor];
        userFriendlyMessage = @"Connected and receiving notifications.";
    } else if ([currentStatus isEqualToString:@"ServerConfigBad"]) {
        backgroundColor = [UIColor purpleColor];
        userFriendlyMessage = @"The server configuration is incorrect.";
    } else if ([currentStatus isEqualToString:@"ConnectionClosed"]) {
        backgroundColor = [UIColor orangeColor];
        userFriendlyMessage = @"Connection closed. Reconnectingâ¦";
    } else {
        backgroundColor = [UIColor darkGrayColor];
        userFriendlyMessage = currentStatus ?: @"Unknown status";
    }

    self.logLabel.backgroundColor = [backgroundColor colorWithAlphaComponent:alpha];
    self.logLabel.text = userFriendlyMessage;
}

- (UIColor *)scanlinePattern {
    UIGraphicsBeginImageContextWithOptions(CGSizeMake(1, 2), NO, 0.0);
    CGContextRef context = UIGraphicsGetCurrentContext();
    
    // Top pixel: Transparent/Bright
    [[UIColor clearColor] setFill];
    CGContextFillRect(context, CGRectMake(0, 0, 1, 1));
    
    // Bottom pixel: Dark/Scanline
    [[UIColor colorWithWhite:0.0 alpha:0.3] setFill];
    CGContextFillRect(context, CGRectMake(0, 1, 1, 1));
    
    UIImage *image = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    
    return [UIColor colorWithPatternImage:image];
}

@end