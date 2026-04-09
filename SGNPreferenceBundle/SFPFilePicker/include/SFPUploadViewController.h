/*
 * SFPUploadViewController.h
 * Compile with -fno-objc-arc.
 */

#import <UIKit/UIKit.h>

@class SFHTTPServer;

@interface SFPUploadViewController : UIViewController {
    SFHTTPServer  *_server;
    NSString      *_directory;
    UIScrollView  *_scrollView;
    UILabel       *_logLabel;
    UIToolbar     *_bottomBar;
    UIProgressView *_progressView;
    UILabel       *_percentLabel;
}

- (id)initWithDirectory:(NSString *)directory;

@end