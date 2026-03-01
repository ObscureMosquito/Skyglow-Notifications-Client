#import "SNLogViewController.h"
#import "SNDataManager.h"

@interface SNLogViewController ()
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, assign) SGState lastKnownState;
@property (nonatomic, strong) CAGradientLayer *gradientLayer;
@end

@implementation SNLogViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    self.view.backgroundColor = [UIColor clearColor];

    self.statusLabel = [[UILabel alloc] initWithFrame:self.view.bounds];
    self.statusLabel.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.layer.cornerRadius = 7.0;
    self.statusLabel.clipsToBounds = YES;
    self.statusLabel.font = [UIFont boldSystemFontOfSize:14.0];
    self.statusLabel.textColor = [UIColor whiteColor];
    
    [self.view addSubview:self.statusLabel];
    
    self.gradientLayer = [CAGradientLayer layer];
    self.gradientLayer.frame = self.view.bounds;
    self.gradientLayer.colors = @[(id)[[UIColor colorWithWhite:1.0 alpha:0.15] CGColor],
                                  (id)[[UIColor colorWithWhite:0.0 alpha:0.15] CGColor]];
    [self.statusLabel.layer addSublayer:self.gradientLayer];
    
    self.lastKnownState = (SGState)-1; // Force immediate update
    [self refreshDaemonStatus];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    self.statusLabel.frame = self.view.bounds;
    self.gradientLayer.frame = self.statusLabel.bounds;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    self.lastKnownState = (SGState)-1; // Force UI refresh on re-appear
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(refreshDaemonStatus) name:@"SNDaemonStatusUpdated" object:nil];
    [[SNDataManager shared] startWatchingDaemonStatus];
    [self refreshDaemonStatus];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    if ([self isMovingFromParentViewController] || [self isBeingDismissed]) {
        [[NSNotificationCenter defaultCenter] removeObserver:self name:@"SNDaemonStatusUpdated" object:nil];
        [[SNDataManager shared] stopWatchingDaemonStatus];
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
    
    void (^updateBlock)(void) = ^{
        self.statusLabel.backgroundColor = [bgColor colorWithAlphaComponent:0.9];
        self.statusLabel.text = labelText;
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

@end