#import "SNLogViewController.h"

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
                                    &daemonStatusDisabled,
                                    CFSTR(kDaemonStatusDisabled),
                                    NULL,
                                    CFNotificationSuspensionBehaviorDeliverImmediately);
    
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                    (__bridge const void *)(self),
                                    &daemonStatusError,
                                    CFSTR(kDaemonStatusError),
                                    NULL,
                                    CFNotificationSuspensionBehaviorDeliverImmediately);
    
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                    (__bridge const void *)(self),
                                    &daemonStatusEnabledNotConnected,
                                    CFSTR(kDaemonStatusEnabledNotConnected),
                                    NULL,
                                    CFNotificationSuspensionBehaviorDeliverImmediately);
    
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                    (__bridge const void *)(self),
                                    &daemonStatusConnected,
                                    CFSTR(kDaemonStatusConnected),
                                    NULL,
                                    CFNotificationSuspensionBehaviorDeliverImmediately);
    
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                    (__bridge const void *)(self),
                                    &daemonStatusBadPort,
                                    CFSTR(kDaemonStatusBadPort),
                                    NULL,
                                    CFNotificationSuspensionBehaviorDeliverImmediately);
    
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                    (__bridge const void *)(self),
                                    &daemonStatusBadIP,
                                    CFSTR(kDaemonStatusBadIP),
                                    NULL,
                                    CFNotificationSuspensionBehaviorDeliverImmediately);
    
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                    (__bridge const void *)(self),
                                    &daemonStatusDecryptError,
                                    CFSTR(kDaemonStatusDecryptError),
                                    NULL,
                                    CFNotificationSuspensionBehaviorDeliverImmediately);
    
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                    (__bridge const void *)(self),
                                    &daemonStatusEncryptError,
                                    CFSTR(kDaemonStatusEncryptError),
                                    NULL,
                                    CFNotificationSuspensionBehaviorDeliverImmediately);
    
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                    (__bridge const void *)(self),
                                    &daemonStatusConnectionClosed,
                                    CFSTR(kDaemonStatusConnectionClosed),
                                    NULL,
                                    CFNotificationSuspensionBehaviorDeliverImmediately);

    NSLog(@"SNLogViewController: Registered for notifications.");
}

- (void)dealloc {
    // Remove observers
    CFNotificationCenterRemoveObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                       (__bridge const void *)(self),
                                       CFSTR(kDaemonStatusDisabled),
                                       NULL);
    
    CFNotificationCenterRemoveObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                       (__bridge const void *)(self),
                                       CFSTR(kDaemonStatusError),
                                       NULL);
    
    CFNotificationCenterRemoveObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                       (__bridge const void *)(self),
                                       CFSTR(kDaemonStatusEnabledNotConnected),
                                       NULL);
    
    CFNotificationCenterRemoveObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                       (__bridge const void *)(self),
                                       CFSTR(kDaemonStatusConnected),
                                       NULL);
    
    CFNotificationCenterRemoveObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                       (__bridge const void *)(self),
                                       CFSTR(kDaemonStatusBadPort),
                                       NULL);
    
    CFNotificationCenterRemoveObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                       (__bridge const void *)(self),
                                       CFSTR(kDaemonStatusBadIP),
                                       NULL);
    
    CFNotificationCenterRemoveObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                       (__bridge const void *)(self),
                                       CFSTR(kDaemonStatusDecryptError),
                                       NULL);
    
    CFNotificationCenterRemoveObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                       (__bridge const void *)(self),
                                       CFSTR(kDaemonStatusEncryptError),
                                       NULL);
    
    CFNotificationCenterRemoveObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                       (__bridge const void *)(self),
                                       CFSTR(kDaemonStatusConnectionClosed),
                                       NULL);

    NSLog(@"SNLogViewController: Observers removed.");
}

void daemonStatusDisabled(CFNotificationCenterRef center,
                          void *observer,
                          CFStringRef name,
                          const void *object,
                          CFDictionaryRef userInfo) {
    SNLogViewController *self = (__bridge SNLogViewController *)observer;
    NSLog(@"SNLogViewController: DaemonStatusDisabled notification received.");
    dispatch_async(dispatch_get_main_queue(), ^{
        [self updateLogWithStatus:@"Disabled"];
    });
}

void daemonStatusError(CFNotificationCenterRef center,
                       void *observer,
                       CFStringRef name,
                       const void *object,
                       CFDictionaryRef userInfo) {
    SNLogViewController *self = (__bridge SNLogViewController *)observer;
    NSLog(@"SNLogViewController: DaemonStatusError notification received.");
    dispatch_async(dispatch_get_main_queue(), ^{
        [self updateLogWithStatus:@"Error"];
    });
}

void daemonStatusEnabledNotConnected(CFNotificationCenterRef center,
                                     void *observer,
                                     CFStringRef name,
                                     const void *object,
                                     CFDictionaryRef userInfo) {
    SNLogViewController *self = (__bridge SNLogViewController *)observer;
    NSLog(@"SNLogViewController: DaemonStatusEnabledNotConnected notification received.");
    dispatch_async(dispatch_get_main_queue(), ^{
        [self updateLogWithStatus:@"EnabledNotConnected"];
    });
}

void daemonStatusConnected(CFNotificationCenterRef center,
                           void *observer,
                           CFStringRef name,
                           const void *object,
                           CFDictionaryRef userInfo) {
    SNLogViewController *self = (__bridge SNLogViewController *)observer;
    NSLog(@"SNLogViewController: DaemonStatusConnected notification received.");
    dispatch_async(dispatch_get_main_queue(), ^{
        [self updateLogWithStatus:@"Connected"];
    });
}

void daemonStatusBadPort(CFNotificationCenterRef center,
                         void *observer,
                         CFStringRef name,
                         const void *object,
                         CFDictionaryRef userInfo) {
    SNLogViewController *self = (__bridge SNLogViewController *)observer;
    NSLog(@"SNLogViewController: DaemonStatusBadPort notification received.");
    dispatch_async(dispatch_get_main_queue(), ^{
        [self updateLogWithStatus:@"DaemonStatusBadPort"];
    });
}

void daemonStatusBadIP(CFNotificationCenterRef center,
                       void *observer,
                       CFStringRef name,
                       const void *object,
                       CFDictionaryRef userInfo) {
    SNLogViewController *self = (__bridge SNLogViewController *)observer;
    NSLog(@"SNLogViewController: DaemonStatusBadIP notification received.");
    dispatch_async(dispatch_get_main_queue(), ^{
        [self updateLogWithStatus:@"DaemonStatusBadIP"];
    });
}

void daemonStatusDecryptError(CFNotificationCenterRef center,
                              void *observer,
                              CFStringRef name,
                              const void *object,
                              CFDictionaryRef userInfo) {
    SNLogViewController *self = (__bridge SNLogViewController *)observer;
    NSLog(@"SNLogViewController: DaemonStatusDecryptError notification received.");
    dispatch_async(dispatch_get_main_queue(), ^{
        [self updateLogWithStatus:@"DaemonStatusDecryptError"];
    });
}

void daemonStatusEncryptError(CFNotificationCenterRef center,
                              void *observer,
                              CFStringRef name,
                              const void *object,
                              CFDictionaryRef userInfo) {
    SNLogViewController *self = (__bridge SNLogViewController *)observer;
    NSLog(@"SNLogViewController: DaemonStatusEncryptError notification received.");
    dispatch_async(dispatch_get_main_queue(), ^{
        [self updateLogWithStatus:@"DaemonStatusEncryptError"];
    });
}

void daemonStatusConnectionClosed(CFNotificationCenterRef center,
                                  void *observer,
                                  CFStringRef name,
                                  const void *object,
                                  CFDictionaryRef userInfo) {
    SNLogViewController *self = (__bridge SNLogViewController *)observer;
    NSLog(@"SNLogViewController: DaemonStatusConnectionClosed notification received.");
    dispatch_async(dispatch_get_main_queue(), ^{
        [self updateLogWithStatus:@"DaemonStatusConnectionClosed"];
    });
}

- (void)updateLogWithStatus:(NSString *)status {
    NSLog(@"SNLogViewController: Updating log with status: %@", status);

    NSString *userFriendlyMessage;
    UIColor *backgroundColor;
    CGFloat alpha = 0.5; // Adjust this value to set the desired opacity (0.0 to 1.0)

    if ([status isEqualToString:@"Disabled"]) {
        backgroundColor = [[UIColor grayColor] colorWithAlphaComponent:alpha];
        userFriendlyMessage = @"The daemon is currently disabled.";
    } else if ([status isEqualToString:@"Error"]) {
        backgroundColor = [[UIColor redColor] colorWithAlphaComponent:alpha];
        userFriendlyMessage = @"An error has occurred. Please check the daemon.";
    } else if ([status isEqualToString:@"EnabledNotConnected"]) {
        backgroundColor = [[UIColor yellowColor] colorWithAlphaComponent:alpha];
        userFriendlyMessage = @"The daemon is enabled but not connected.";
    } else if ([status isEqualToString:@"Connected"]) {
        backgroundColor = [[UIColor greenColor] colorWithAlphaComponent:alpha];
        userFriendlyMessage = @"The daemon is connected successfully.";
    } else if ([status isEqualToString:@"DaemonStatusBadPort"]) {
        backgroundColor = [[UIColor orangeColor] colorWithAlphaComponent:alpha];
        userFriendlyMessage = @"The port number is invalid or missing.";
    } else if ([status isEqualToString:@"DaemonStatusBadIP"]) {
        backgroundColor = [[UIColor purpleColor] colorWithAlphaComponent:alpha];
        userFriendlyMessage = @"The IP address is invalid or missing.";
    } else if ([status isEqualToString:@"DaemonStatusDecryptError"]) {
        backgroundColor = [[UIColor magentaColor] colorWithAlphaComponent:alpha];
        userFriendlyMessage = @"Error decrypting the server's data.";
    } else if ([status isEqualToString:@"DaemonStatusEncryptError"]) {
        backgroundColor = [[UIColor cyanColor] colorWithAlphaComponent:alpha];
        userFriendlyMessage = @"Error encrypting the data.";
    } else if ([status isEqualToString:@"DaemonStatusConnectionClosed"]) {
        backgroundColor = [[UIColor brownColor] colorWithAlphaComponent:alpha];
        userFriendlyMessage = @"The connection was closed.";
    }

    self.logTextView.backgroundColor = backgroundColor;
    self.logTextView.text = userFriendlyMessage;
}

@end
