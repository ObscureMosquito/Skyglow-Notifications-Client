#import "SNLogViewController.h"
#import "SNDataManager.h"

@interface SNLogViewController ()
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, assign) SGState lastKnownState;
@property (nonatomic, strong) CAGradientLayer *gradientLayer;
@property (nonatomic, copy)   NSString *currentErrorDetail;
@property (nonatomic, copy)   NSString *currentRecoverySuggestion;
@end

@implementation SNLogViewController

/* iOS 4-5 PSRootController calls these on every pushed VC during the
 * back-pop sequence, even on plain UIViewControllers.  Crashes with
 * "unrecognized selector" otherwise. */
- (void)setRootController:(id)controller   {}
- (void)setParentController:(id)controller {}
- (void)setSpecifier:(id)specifier         {}

- (void)viewDidLoad {
    [super viewDidLoad];

    self.view.backgroundColor = [UIColor clearColor];

    UILabel *label = [[UILabel alloc] initWithFrame:self.view.bounds];
    self.statusLabel = label;
    [label release];
    self.statusLabel.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.statusLabel.textAlignment = (NSTextAlignment)UITextAlignmentCenter;
    self.statusLabel.clipsToBounds = YES;
    self.statusLabel.font = [UIFont boldSystemFontOfSize:13.0];
    self.statusLabel.textColor = [UIColor whiteColor];
    self.statusLabel.adjustsFontSizeToFitWidth = YES;
    self.statusLabel.minimumFontSize = 9.0;

    [self.view addSubview:self.statusLabel];

    self.gradientLayer = [CAGradientLayer layer];
    self.gradientLayer.frame = self.view.bounds;
    self.gradientLayer.colors = [NSArray arrayWithObjects:
                                 (id)[[UIColor colorWithWhite:1.0 alpha:0.15] CGColor],
                                 (id)[[UIColor colorWithWhite:0.0 alpha:0.15] CGColor],
                                 nil];
    [self.statusLabel.layer addSublayer:self.gradientLayer];

    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    UIImageView *overlay = [[UIImageView alloc]
        initWithImage:[UIImage imageWithContentsOfFile:
                        [bundle pathForResource:@"Gloss" ofType:@"png"]]];
    overlay.frame             = self.statusLabel.bounds;
    overlay.autoresizingMask  = UIViewAutoresizingFlexibleWidth |
                                UIViewAutoresizingFlexibleHeight;
    overlay.contentMode       = UIViewContentModeScaleToFill;
    overlay.userInteractionEnabled = NO;
    overlay.alpha = 0.4;
    [self.statusLabel addSubview:overlay];

    [overlay release];

    self.statusLabel.numberOfLines = 2;
    self.statusLabel.userInteractionEnabled = NO;
    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc]
        initWithTarget:self action:@selector(_statusLabelTapped)];
    tap.cancelsTouchesInView = NO;
    [self.statusLabel addGestureRecognizer:tap];

    [tap release];

    self.lastKnownState = (SGState)-1;

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(refreshDaemonStatus)
                                                 name:@"SNDaemonStatusUpdated"
                                               object:nil];
    [self refreshDaemonStatus];
}

- (void)viewDidLayoutSubviews {
    if ([[UIViewController class] instancesRespondToSelector:@selector(viewDidLayoutSubviews)]) {
        [super viewDidLayoutSubviews];
    }
    self.statusLabel.frame = self.view.bounds;
    self.gradientLayer.frame = self.statusLabel.bounds;
}

- (void)viewDidUnload {
    [super viewDidUnload];
    self.statusLabel = nil;
    self.gradientLayer = nil;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    self.lastKnownState = (SGState)-1;

    [[NSNotificationCenter defaultCenter] removeObserver:self name:@"SNDaemonStatusUpdated" object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(refreshDaemonStatus) name:@"SNDaemonStatusUpdated" object:nil];
    [self refreshDaemonStatus];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];

    [_statusLabel release];
    [_gradientLayer release];
    [_currentErrorDetail release];
    [_currentRecoverySuggestion release];

    [super dealloc];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    BOOL leaving = YES;
    if ([self respondsToSelector:@selector(isMovingFromParentViewController)]) {
        leaving = [self isMovingFromParentViewController] || [self isBeingDismissed];
    }
    if (leaving) {
        [[NSNotificationCenter defaultCenter] removeObserver:self name:@"SNDaemonStatusUpdated" object:nil];
    }
}

- (void)refreshDaemonStatus {
    SGStatusPayload payload = [[SNDataManager shared] latestPayload];

    BOOL animate = (self.lastKnownState != payload.state);
    self.lastKnownState = payload.state;

    UIColor *bgColor = [[SNDataManager shared] colorForState:self.lastKnownState];
    NSString *labelText = [[SNDataManager shared] friendlyStringForState:self.lastKnownState];

    if (payload.state == SGStateBackingOff && payload.currentBackoffSec > 0) {
        labelText = [NSString stringWithFormat:@"%@ (Retry in %us)", labelText, payload.currentBackoffSec];
    } else if (payload.state == SGStateConnecting && payload.consecutiveFailures > 0) {
        labelText = [NSString stringWithFormat:@"%@ (Attempt %u)", labelText, payload.consecutiveFailures + 1];
    }

    NSString *errDetail = nil;
    if (payload.errorDetail[0] != '\0') {
        payload.errorDetail[sizeof(payload.errorDetail) - 1] = '\0';
        errDetail = [NSString stringWithUTF8String:payload.errorDetail];
    }
    self.currentErrorDetail = errDetail;
    self.currentRecoverySuggestion = [[SNDataManager shared] recoverySuggestionForState:payload.state];

    if (errDetail.length > 0) {
        labelText = [NSString stringWithFormat:@"%@\n%@", labelText, errDetail];
    }

    if (payload.state == SGStateConnected && payload.activeProfileIndex > 0) {
        labelText = [NSString stringWithFormat:@"%@ (Profile %u)", labelText, payload.activeProfileIndex];
    }

    NSString *capturedText = labelText;
    void (^updateBlock)(void) = ^{
        self.statusLabel.backgroundColor = [bgColor colorWithAlphaComponent:0.9];
        self.statusLabel.text = capturedText;
    };

    if (animate) {
        [UIView transitionWithView:self.statusLabel
                          duration:0.25
                           options:UIViewAnimationOptionTransitionCrossDissolve
                        animations:updateBlock
                        completion:nil];
    } else {
        updateBlock();
    }
}

- (void)_statusLabelTapped {
    NSString *detail = self.currentErrorDetail;
    NSString *suggestion = self.currentRecoverySuggestion;
    if (!detail && !suggestion) return;

    NSMutableString *msg = [NSMutableString string];
    if (detail)     [msg appendString:detail];
    if (suggestion) {
        if (msg.length > 0) [msg appendString:@"\n\n"];
        [msg appendString:suggestion];
    }

    UIAlertView *av = [[UIAlertView alloc]
                       initWithTitle:@"Status Detail"
                             message:msg
                            delegate:nil
                   cancelButtonTitle:@"OK"
                   otherButtonTitles:nil];
    [av show];
    [av release];
}

@end
