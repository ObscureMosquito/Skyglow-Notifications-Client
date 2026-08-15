#import "SNStatusBannerViewController.h"
#import "SNDataManager.h"
#import "SNAlert.h"

@interface SNStatusBannerViewController ()
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UILabel *primaryLabel;
@property (nonatomic, strong) UILabel *detailLabel;
@property (nonatomic, strong) UIImageView *glossOverlay;
@property (nonatomic, assign) SGState lastKnownState;
@property (nonatomic, strong) CAGradientLayer *gradientLayer;
@property (nonatomic, copy)   NSString *currentErrorDetail;
@property (nonatomic, copy)   NSString *currentRecoverySuggestion;
@property (nonatomic, assign) CGFloat statusLineSpacing;
@end

@implementation SNStatusBannerViewController

- (void)setRootController:(id)controller   {}
- (void)setParentController:(id)controller {}
- (void)setSpecifier:(id)specifier         {}
- (void)willResignActive                   {}
- (void)willBecomeActive                   {}

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
    self.glossOverlay = overlay;
    [overlay release];

    self.glossOverlay.frame = [self _glossFrameForBounds:self.statusLabel.bounds];
    self.glossOverlay.autoresizingMask = UIViewAutoresizingFlexibleWidth |
                                         UIViewAutoresizingFlexibleHeight;
    self.glossOverlay.contentMode  = UIViewContentModeScaleToFill;
    self.glossOverlay.userInteractionEnabled = NO;
    self.glossOverlay.alpha = 0.4;
    [self.statusLabel addSubview:self.glossOverlay];

    self.statusLabel.userInteractionEnabled = NO;
    self.statusLineSpacing = 6.0f;
    self.primaryLabel = [self _makeLineLabel];
    self.detailLabel  = [self _makeLineLabel];
    [self.statusLabel insertSubview:self.primaryLabel belowSubview:self.glossOverlay];
    [self.statusLabel insertSubview:self.detailLabel  belowSubview:self.glossOverlay];

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
    if (self.glossOverlay) {
        self.glossOverlay.frame = [self _glossFrameForBounds:self.statusLabel.bounds];
    }
    [self _layoutStatusLabels];
}

- (CGRect)_glossFrameForBounds:(CGRect)bounds {
    if ([[[UIDevice currentDevice] systemVersion] floatValue] >= 7.0f) {
        return CGRectMake(0.0f, -2.0f,
                          bounds.size.width, bounds.size.height + 4.0f);
    }
    return bounds;
}

- (UILabel *)_makeLineLabel {
    UILabel *label = [[[UILabel alloc] init] autorelease];
    label.backgroundColor          = [UIColor clearColor];
    label.textAlignment            = (NSTextAlignment)UITextAlignmentCenter;
    label.font                     = [UIFont boldSystemFontOfSize:13.0];
    label.textColor                = [UIColor whiteColor];
    label.adjustsFontSizeToFitWidth = YES;
    label.minimumFontSize          = 9.0;
    label.numberOfLines            = 1;
    label.userInteractionEnabled   = NO;  /* let taps reach statusLabel's recognizer */
    return label;
}

- (void)_applyStatusText:(NSString *)text {
    if (!self.statusLabel) {
        return;
    }

    NSString *primary = text ?: @"";
    NSString *detail  = nil;
    NSRange nl = [primary rangeOfString:@"\n"];
    if (nl.location != NSNotFound) {
        detail  = [primary substringFromIndex:nl.location + 1];
        primary = [primary substringToIndex:nl.location];
    }

    self.primaryLabel.text = primary;
    self.detailLabel.text  = detail ?: @"";
    self.detailLabel.hidden = (detail.length == 0);
    [self _layoutStatusLabels];
}

- (void)_layoutStatusLabels {
    BOOL animationsWereEnabled = [UIView areAnimationsEnabled];
    [UIView setAnimationsEnabled:NO];

    CGRect bounds = self.statusLabel.bounds;
    CGFloat lineHeight = ceilf([@"Ag" sizeWithFont:self.primaryLabel.font].height);

    if (self.detailLabel.hidden) {
        self.primaryLabel.frame = bounds;
    } else {
        CGFloat blockHeight = lineHeight * 2.0f + self.statusLineSpacing;
        CGFloat top = floorf((bounds.size.height - blockHeight) / 2.0f);
        self.primaryLabel.frame = CGRectMake(0.0f, top, bounds.size.width, lineHeight);
        self.detailLabel.frame  = CGRectMake(0.0f,
                                             top + lineHeight + self.statusLineSpacing,
                                             bounds.size.width, lineHeight);
    }

    [UIView setAnimationsEnabled:animationsWereEnabled];
}

- (void)viewDidUnload {
    [super viewDidUnload];
    self.statusLabel = nil;
    self.primaryLabel = nil;
    self.detailLabel = nil;
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
    [_primaryLabel release];
    [_detailLabel release];
    [_glossOverlay release];
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
        [self _applyStatusText:capturedText];
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

    [SNAlert presentMessage:msg title:@"Status Detail" from:self];
}

@end
