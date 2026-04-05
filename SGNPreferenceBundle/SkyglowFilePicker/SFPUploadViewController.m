/*
 * SFPUploadViewController.m
 * Compile with -fno-objc-arc.
 */

#import "SFPUploadViewController.h"
#import "HTTP/SFHTTPServer.h"

@interface SFPUploadViewController () <SFHTTPServerDelegate>
- (void)_cancelTapped;
- (void)_appendLog:(NSString *)line;
- (void)_dismissSelfAnimated:(BOOL)animated;
- (void)_setUploadProgress:(float)progress;
@end

@implementation SFPUploadViewController

- (id)initWithDirectory:(NSString *)directory {
    self = [super initWithNibName:nil bundle:nil];
    if (self) {
        _directory = [directory copy];
        _server    = [[SFHTTPServer alloc] init];
        self.title = @"HTTP Upload";
    }
    return self;
}

- (void)dealloc {
    [_server stop];
    [_server release];
    [_directory release];
    [_logLabel release];
    [_scrollView release];
    [_bottomBar release];
    [_progressView release];
    [_percentLabel release];
    [super dealloc];
}

- (void)loadView {
    CGRect frame = [[UIScreen mainScreen] applicationFrame];

    UIView *root = [[UIView alloc] initWithFrame:frame];
    root.backgroundColor = [UIColor blackColor];
    self.view = root;
    [root release];
}

- (void)viewDidLoad {
    [super viewDidLoad];

    self.view.backgroundColor = [UIColor blackColor];

    UIBarButtonItem *cancel =
        [[[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemCancel
                                                       target:self
                                                       action:@selector(_cancelTapped)] autorelease];
    self.navigationItem.leftBarButtonItem = cancel;

    CGRect bounds = self.view.bounds;
    CGFloat barH = 44.0f;

    _scrollView = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 0, bounds.size.width, bounds.size.height - barH)];
    _scrollView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    _scrollView.backgroundColor = [UIColor blackColor];
    _scrollView.scrollEnabled = NO;
    _scrollView.showsHorizontalScrollIndicator = NO;
    _scrollView.showsVerticalScrollIndicator = YES;

    if ([_scrollView respondsToSelector:@selector(setAlwaysBounceHorizontal:)]) {
        [_scrollView setAlwaysBounceHorizontal:NO];
    }
    if ([_scrollView respondsToSelector:@selector(setAlwaysBounceVertical:)]) {
        [_scrollView setAlwaysBounceVertical:NO];
    }

    [self.view addSubview:_scrollView];

    _logLabel = [[UILabel alloc] initWithFrame:CGRectMake(8, 8, bounds.size.width - 16, 0)];
    _logLabel.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    _logLabel.backgroundColor = [UIColor clearColor];
    _logLabel.textColor = [UIColor whiteColor];
    _logLabel.font = [UIFont fontWithName:@"Courier" size:13.0f];
    if (!_logLabel.font) {
        _logLabel.font = [UIFont systemFontOfSize:13.0f];
    }
    _logLabel.numberOfLines = 0;
    _logLabel.lineBreakMode = UILineBreakModeCharacterWrap;
    _logLabel.text = @"";
    [_scrollView addSubview:_logLabel];

    _bottomBar = [[UIToolbar alloc] initWithFrame:CGRectMake(0, bounds.size.height - barH, bounds.size.width, barH)];
    _bottomBar.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleTopMargin;
    [self.view addSubview:_bottomBar];

    UIView *progressContainer = [[[UIView alloc] initWithFrame:CGRectMake(0, 0, bounds.size.width - 80.0f, 20.0f)] autorelease];
    progressContainer.backgroundColor = [UIColor clearColor];

    _progressView = [[UIProgressView alloc] initWithProgressViewStyle:UIProgressViewStyleDefault];
    _progressView.frame = CGRectMake(0, 8, progressContainer.bounds.size.width, 10);
    _progressView.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    _progressView.progress = 0.0f;
    [progressContainer addSubview:_progressView];

    UIBarButtonItem *progressItem = [[[UIBarButtonItem alloc] initWithCustomView:progressContainer] autorelease];

    _percentLabel = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, 44, 20)];
    _percentLabel.backgroundColor = [UIColor clearColor];
    _percentLabel.textColor = [UIColor blackColor];
    _percentLabel.font = [UIFont boldSystemFontOfSize:13.0f];
    _percentLabel.textAlignment = UITextAlignmentRight;
    _percentLabel.text = @"0%";

    UIBarButtonItem *percentItem = [[[UIBarButtonItem alloc] initWithCustomView:_percentLabel] autorelease];
    UIBarButtonItem *flex = [[[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace
                                                                            target:nil
                                                                            action:nil] autorelease];

    [_bottomBar setItems:[NSArray arrayWithObjects:progressItem, flex, percentItem, nil] animated:NO];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];

    if (_server.boundPort != 0) return;

    [self _setUploadProgress:0.0f];

    if ([_server startInDirectory:_directory startPort:8080 delegate:self]) {
        NSString *ip = [SFHTTPServer localIPAddress];
        if (!ip) ip = @"0.0.0.0";

        NSString *url = [NSString stringWithFormat:@"http://%@:%u",
                         ip, (unsigned)_server.boundPort];
        [self _appendLog:url];
    } else {
        [self _appendLog:@"Failed to start server."];
    }
}

- (void)_cancelTapped {
    [_server stop];
    [self _dismissSelfAnimated:YES];
}

- (void)_dismissSelfAnimated:(BOOL)animated {
    UIViewController *presenter = nil;

    if ([self respondsToSelector:@selector(parentViewController)]) {
        presenter = [self parentViewController];
    }

    if ([self respondsToSelector:@selector(dismissViewControllerAnimated:completion:)]) {
        [self dismissViewControllerAnimated:animated completion:nil];
    } else if (presenter &&
               [presenter respondsToSelector:@selector(dismissModalViewControllerAnimated:)]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        [presenter dismissModalViewControllerAnimated:animated];
#pragma clang diagnostic pop
    } else if (self.navigationController &&
               [self.navigationController respondsToSelector:@selector(dismissModalViewControllerAnimated:)]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        [self.navigationController dismissModalViewControllerAnimated:animated];
#pragma clang diagnostic pop
    }
}

- (void)_setUploadProgress:(float)progress {
    if (progress < 0.0f) progress = 0.0f;
    if (progress > 1.0f) progress = 1.0f;

    [_progressView setProgress:progress];
    _percentLabel.text = [NSString stringWithFormat:@"%d%%", (int)(progress * 100.0f + 0.5f)];
}

- (void)_appendLog:(NSString *)line {
    if (!line) return;

    NSString *cur = _logLabel.text ? _logLabel.text : @"";
    NSString *next = (cur.length > 0)
                   ? [cur stringByAppendingFormat:@"\n%@", line]
                   : line;
    _logLabel.text = next;

    CGFloat width = _scrollView.bounds.size.width - 16.0f;
    if (width < 1.0f) width = 1.0f;

    CGSize maxSize = CGSizeMake(width, 99999.0f);
    CGSize fit = [_logLabel.text sizeWithFont:_logLabel.font
                            constrainedToSize:maxSize
                                lineBreakMode:_logLabel.lineBreakMode];

    _logLabel.frame = CGRectMake(8, 8, width, fit.height);

    CGFloat contentH = fit.height + 16.0f;
    CGFloat visibleH = _scrollView.bounds.size.height;
    BOOL overflows = (contentH > visibleH);

    if (!overflows) {
        contentH = visibleH;
    }

    _scrollView.contentSize = CGSizeMake(_scrollView.bounds.size.width, contentH);
    _scrollView.scrollEnabled = overflows;

    if ([_scrollView respondsToSelector:@selector(setAlwaysBounceVertical:)]) {
        [_scrollView setAlwaysBounceVertical:NO];
    }
    if ([_scrollView respondsToSelector:@selector(setAlwaysBounceHorizontal:)]) {
        [_scrollView setAlwaysBounceHorizontal:NO];
    }

    if (overflows) {
        CGFloat y = contentH - visibleH;
        [_scrollView setContentOffset:CGPointMake(0, y) animated:NO];
    } else {
        [_scrollView setContentOffset:CGPointZero animated:NO];
    }
}

#pragma mark - SFHTTPServerDelegate

- (void)httpServer:(SFHTTPServer *)server didLog:(NSString *)message {
    if ([NSThread isMainThread]) {
        [self _appendLog:message];
    } else {
        [self performSelectorOnMainThread:@selector(_appendLog:)
                               withObject:message
                            waitUntilDone:NO];
    }
}

- (void)httpServer:(SFHTTPServer *)server didUpdateUploadProgress:(float)progress {
    if ([NSThread isMainThread]) {
        [self _setUploadProgress:progress];
    } else {
        NSNumber *num = [NSNumber numberWithFloat:progress];
        [self performSelectorOnMainThread:@selector(_setUploadProgressFromNumber:)
                               withObject:num
                            waitUntilDone:NO];
    }
}

- (void)_setUploadProgressFromNumber:(NSNumber *)number {
    [self _setUploadProgress:[number floatValue]];
}

@end