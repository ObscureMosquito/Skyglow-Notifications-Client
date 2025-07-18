#import "SNLogViewController.h"
#include <Foundation/Foundation.h>

@interface SNLogViewController ()

@property (nonatomic, strong) UITextView *logTextView;

@end

@implementation SNLogViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    CGFloat offset = -39.0;
    CGRect frame = CGRectMake(0, offset, self.view.bounds.size.width, self.view.bounds.size.height);

    self.logTextView = [[UITextView alloc] initWithFrame:frame];
    self.logTextView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.logTextView.editable = NO;
    self.logTextView.textAlignment = NSTextAlignmentCenter;
    self.logTextView.center = CGPointMake(self.view.center.x, self.view.center.y + offset / 2);
    self.logTextView.layer.cornerRadius = 7;
    self.logTextView.clipsToBounds = YES;
    [self.view addSubview:self.logTextView];
    
    // Register for each status notification
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                    (__bridge const void *)(self),
                                    &daemonStatusStatusUpdate,
                                    CFSTR(kDaemonStatusNewStatus),
                                    NULL,
                                    CFNotificationSuspensionBehaviorDeliverImmediately);

    NSLog(@"SNLogViewController: Registered for notifications.");
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
    CGFloat alpha = 0.5; // Adjust this value to set the desired opacity (0.0 to 1.0)

    if ([currentStatus isEqualToString:@"Disabled"]) {
        backgroundColor = [UIColor grayColor];
        userFriendlyMessage = @"The daemon is currently disabled.";
    } else if ([currentStatus isEqualToString:@"Error"]) {
        backgroundColor = [UIColor redColor];
        userFriendlyMessage = @"An error has occurred. Please check the daemon.";
    } else if ([currentStatus isEqualToString:@"EnabledNotConnected"]) {
        backgroundColor = [UIColor yellowColor];
        userFriendlyMessage = @"The daemon is enabled but not connected.";
    } else if ([currentStatus isEqualToString:@"ConnectedNotAuthenticated"]) {
        backgroundColor = [UIColor orangeColor];
        userFriendlyMessage = @"The daemon is connected but not authenticated.";
    }else if ([currentStatus isEqualToString:@"Connected"]) {
        backgroundColor = [UIColor greenColor];
        userFriendlyMessage = @"The daemon is connected successfully.";
    } else if ([currentStatus isEqualToString:@"ServerConfigBad"]) {
        backgroundColor = [UIColor purpleColor];
        userFriendlyMessage = @"The server configuration is incorrect.";
    } else if ([currentStatus isEqualToString:@"DaemonStatusConnectionClosed"]) {
        backgroundColor = [UIColor brownColor];
        userFriendlyMessage = @"The connection was closed.";
    }

    self.logTextView.backgroundColor = [backgroundColor colorWithAlphaComponent:alpha];
    self.logTextView.text = userFriendlyMessage;
}

@end
