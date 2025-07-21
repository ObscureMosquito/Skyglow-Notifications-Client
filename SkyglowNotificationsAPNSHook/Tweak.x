%hook UIApplication

// iOS 7 & below
- (void)registerForRemoteNotificationTypes:(UIRemoteNotificationType)types {
    NSLog(@"[Skyglow APNS Hook] Intercepted registerForRemoteNotificationTypes: %lu", (unsigned long)types);
    
    // Log which notification types are being requested
    if (types & UIRemoteNotificationTypeBadge) 
        NSLog(@"[Skyglow APNS Hook] Requesting badge notifications");
    if (types & UIRemoteNotificationTypeSound)
        NSLog(@"[Skyglow APNS Hook] Requesting sound notifications");
    if (types & UIRemoteNotificationTypeAlert)
        NSLog(@"[Skyglow APNS Hook] Requesting alert notifications");
    
    // %orig; // Call the original implementation
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        // Create a fake token for testing
        NSString *fakeTokenString = @"SKYGLOWNOTIFYdef0123456789abcdef0123456789abcdef0123456789abcdefwillthisdatagetcut";
        NSData *fakeToken = [fakeTokenString dataUsingEncoding:NSUTF8StringEncoding];
        
        // Find the app delegate
        id<UIApplicationDelegate> delegate = [UIApplication sharedApplication].delegate;
        
        NSLog(@"[Skyglow APNS Hook] About to simulate with delegate: %@ (%@)", delegate, [delegate class]);
        
        // Call the delegate method if it implements it
        if ([delegate respondsToSelector:@selector(application:didRegisterForRemoteNotificationsWithDeviceToken:)]) {
            [delegate application:[UIApplication sharedApplication] didRegisterForRemoteNotificationsWithDeviceToken:fakeToken];
            NSLog(@"[Skyglow APNS Hook] Simulated push notification registration");
        }
    });
}

%end
