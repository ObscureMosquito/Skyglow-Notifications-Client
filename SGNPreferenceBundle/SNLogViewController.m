#import "SNLogViewController.h"
#import "SNDataManager.h"
#import <objc/runtime.h>
#import <objc/message.h>

@interface SNLogViewController ()
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, assign) SGState lastKnownState;
@property (nonatomic, strong) CAGradientLayer *gradientLayer;
@property (nonatomic, copy)   NSString *currentErrorDetail;
@property (nonatomic, copy)   NSString *currentRecoverySuggestion;
@end

@implementation SNLogViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    self.view.backgroundColor = [UIColor clearColor];

    self.statusLabel = [[UILabel alloc] initWithFrame:self.view.bounds];
    self.statusLabel.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    if ([[UIDevice currentDevice].systemVersion floatValue] < 7.0) {
        self.statusLabel.layer.cornerRadius = 7.0;
    }
    self.statusLabel.clipsToBounds = YES;
    self.statusLabel.font = [UIFont boldSystemFontOfSize:13.0];
    self.statusLabel.textColor = [UIColor whiteColor];
    self.statusLabel.adjustsFontSizeToFitWidth = YES;
    self.statusLabel.minimumFontSize = 9.0;

    [self.view addSubview:self.statusLabel];

    self.gradientLayer = [CAGradientLayer layer];
    self.gradientLayer.frame = self.view.bounds;
    self.gradientLayer.colors = @[(id)[[UIColor colorWithWhite:1.0 alpha:0.15] CGColor],
                                  (id)[[UIColor colorWithWhite:0.0 alpha:0.15] CGColor]];
    [self.statusLabel.layer addSublayer:self.gradientLayer];

    self.statusLabel.numberOfLines = 2;
    self.statusLabel.userInteractionEnabled = NO;
    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc]
        initWithTarget:self action:@selector(_statusLabelTapped)];
    tap.cancelsTouchesInView = NO;
    [self.statusLabel addGestureRecognizer:tap];

    self.lastKnownState = (SGState)-1;

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(refreshDaemonStatus)
                                                 name:@"SNDaemonStatusUpdated"
                                               object:nil];
    [[SNDataManager shared] startWatchingDaemonStatus];
    [self refreshDaemonStatus];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    self.statusLabel.frame = self.view.bounds;
    self.gradientLayer.frame = self.statusLabel.bounds;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    self.lastKnownState = (SGState)-1;

    [[NSNotificationCenter defaultCenter] removeObserver:self name:@"SNDaemonStatusUpdated" object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(refreshDaemonStatus) name:@"SNDaemonStatusUpdated" object:nil];
    [[SNDataManager shared] startWatchingDaemonStatus];
    [self refreshDaemonStatus];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [[SNDataManager shared] stopWatchingDaemonStatus];
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

    Class alertControllerClass = NSClassFromString(@"UIAlertController");
    if (alertControllerClass) {
        SEL createSel = NSSelectorFromString(@"alertControllerWithTitle:message:preferredStyle:");
        id (*create)(Class, SEL, id, id, NSInteger) =
            (id (*)(Class, SEL, id, id, NSInteger))objc_msgSend;
        id alert = create(alertControllerClass, createSel, @"Status Detail", msg, 1);

        Class actionClass = NSClassFromString(@"UIAlertAction");
        SEL actionSel = NSSelectorFromString(@"actionWithTitle:style:handler:");
        id (*makeAction)(Class, SEL, id, NSInteger, id) =
            (id (*)(Class, SEL, id, NSInteger, id))objc_msgSend;
        id okAction = makeAction(actionClass, actionSel, @"OK", 1, nil);

        SEL addSel = NSSelectorFromString(@"addAction:");
        void (*addAction)(id, SEL, id) = (void (*)(id, SEL, id))objc_msgSend;
        addAction(alert, addSel, okAction);

        UIViewController *presenter = self;
        while (presenter.parentViewController) presenter = presenter.parentViewController;
        if (!presenter.view.window) {
            UIResponder *r = self.view;
            while (r && ![r isKindOfClass:[UIViewController class]]) r = [r nextResponder];
            if (r) presenter = (UIViewController *)r;
        }

        SEL presentSel = NSSelectorFromString(@"presentViewController:animated:completion:");
        void (*present)(id, SEL, id, BOOL, id) = (void (*)(id, SEL, id, BOOL, id))objc_msgSend;
        present(presenter, presentSel, alert, YES, nil);
    } else {
        UIAlertView *av = [[UIAlertView alloc]
                           initWithTitle:@"Status Detail"
                                 message:msg
                                delegate:nil
                       cancelButtonTitle:@"OK"
                       otherButtonTitles:nil];
        [av show];
    }
}

@end
