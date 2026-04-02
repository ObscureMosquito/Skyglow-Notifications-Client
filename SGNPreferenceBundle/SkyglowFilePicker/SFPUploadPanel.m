/*
 * SFPUploadPanel.m — slide-up Wi-Fi file-upload overlay.
 * Compile with -fno-objc-arc (MRC).
 */

#import "SFPUploadPanel.h"
#import "HTTP/SFHTTPServer.h"

#include <math.h> /* floorf */

@interface SFPUploadPanel () <SFHTTPServerDelegate> {
    UIButton        *_overlayBtn;   /* dim area — tap to dismiss        */
    UIView          *_panelView;    /* solid dark panel at bottom        */
    UITextView      *_logView;      /* terminal-style log output         */
    SFHTTPServer    *_server;       /* owned upload server               */
    NSString        *_directory;    /* destination directory             */
    BOOL             _dismissing;   /* guard against double-dismiss      */
    id               _dismissTarget;/* weak — notified when gone         */
    SEL              _dismissSel;
}
- (void)_appendLog:(NSString *)line;
- (void)_closeTapped;
- (void)_finishDismiss;
- (void)_dismissAnimDone:(NSString *)animId finished:(NSNumber *)fin context:(void *)ctx;
@end

@implementation SFPUploadPanel

- (id)initWithDirectory:(NSString *)dir {
    self = [super initWithFrame:CGRectZero];
    if (self) {
        _directory  = [dir copy];
        _server     = [[SFHTTPServer alloc] init];
        _dismissing = NO;
    }
    return self;
}

- (void)dealloc {
    [_server stop];
    [_server release];
    [_directory release];
    [_overlayBtn release];
    [_panelView release];
    [_logView release];
    [super dealloc];
}

- (void)setDismissTarget:(id)target selector:(SEL)sel {
    _dismissTarget = target; /* intentionally weak */
    _dismissSel    = sel;
}

- (void)showInView:(UIView *)parent {
    CGRect bounds  = parent.bounds;
    CGFloat w      = bounds.size.width;
    CGFloat h      = bounds.size.height;
    CGFloat panelH = floorf(h * 0.58f);
    CGFloat panelY = h - panelH;

    self.frame           = bounds;
    self.backgroundColor = [UIColor clearColor];
    /* Clip so the panel doesn't bleed outside the container on iPad */
    self.clipsToBounds   = YES;

    /* ── Transparent hit-area covering the region above the panel ────────
     * No darkening — purely captures taps so the user can tap outside
     * the panel to dismiss it.                                            */
    _overlayBtn = [[UIButton buttonWithType:UIButtonTypeCustom] retain];
    _overlayBtn.frame           = CGRectMake(0, 0, w, panelY);
    _overlayBtn.backgroundColor = [UIColor clearColor];
    [_overlayBtn addTarget:self
                    action:@selector(_closeTapped)
          forControlEvents:UIControlEventTouchUpInside];
    [self addSubview:_overlayBtn];

    /* ── Panel container — starts off-screen below ──────────────────────── */
    _panelView = [[UIView alloc] initWithFrame:CGRectMake(0, h, w, panelH)];
    _panelView.backgroundColor =
        [UIColor colorWithRed:0.10f green:0.12f blue:0.18f alpha:1.0f];

    /* Rounded top corners via CAShapeLayer mask */
    {
        CGFloat r = 12.0f;
        CGMutablePathRef path = CGPathCreateMutable();
        CGPathMoveToPoint(path, NULL, r, 0);
        CGPathAddLineToPoint(path, NULL, w - r, 0);
        CGPathAddArcToPoint(path, NULL, w, 0, w, r, r);
        CGPathAddLineToPoint(path, NULL, w, panelH);
        CGPathAddLineToPoint(path, NULL, 0, panelH);
        CGPathAddArcToPoint(path, NULL, 0, 0, r, 0, r);
        CGPathCloseSubpath(path);
        CAShapeLayer *maskLayer = [CAShapeLayer layer];
        maskLayer.path = path;
        CGPathRelease(path);
        _panelView.layer.mask = maskLayer;
    }

    /* ── Header bar (sits flush at the top of the panel) ────────────────── */
    UIView *headerBar = [[[UIView alloc] initWithFrame:CGRectMake(0, 0, w, 44)] autorelease];
    headerBar.backgroundColor = [UIColor colorWithWhite:0.0f alpha:0.25f];

    UILabel *titleLbl = [[[UILabel alloc] initWithFrame:CGRectMake(16, 0, w - 80, 44)] autorelease];
    titleLbl.text            = @"Wi-Fi Upload";
    titleLbl.textColor       = [UIColor whiteColor];
    titleLbl.font            = [UIFont boldSystemFontOfSize:17.0f];
    titleLbl.backgroundColor = [UIColor clearColor];
    titleLbl.shadowColor     = [UIColor colorWithWhite:0.0f alpha:0.5f];
    titleLbl.shadowOffset    = CGSizeMake(0, -1);
    [headerBar addSubview:titleLbl];

    UIButton *closeBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    closeBtn.frame = CGRectMake(w - 68, 0, 64, 44);
    [closeBtn setTitle:@"Close" forState:UIControlStateNormal];
    [closeBtn setTitleColor:[UIColor colorWithRed:0.91f green:0.27f blue:0.38f alpha:1.0f]
                  forState:UIControlStateNormal];
    closeBtn.titleLabel.font = [UIFont boldSystemFontOfSize:15.0f];
    [closeBtn addTarget:self
                 action:@selector(_closeTapped)
       forControlEvents:UIControlEventTouchUpInside];
    [headerBar addSubview:closeBtn];
    [_panelView addSubview:headerBar];

    /* Separator line under header */
    UIView *sep = [[[UIView alloc] initWithFrame:CGRectMake(0, 44, w, 1)] autorelease];
    sep.backgroundColor = [UIColor colorWithWhite:1.0f alpha:0.08f];
    [_panelView addSubview:sep];

    /* ── Log text view ──────────────────────────────────────────────────── */
    CGFloat logY = 45;
    CGFloat logH = panelH - logY - 8;
    _logView = [[UITextView alloc] initWithFrame:CGRectMake(0, logY, w, logH)];
    _logView.backgroundColor = [UIColor colorWithRed:0.05f green:0.06f blue:0.09f alpha:1.0f];
    _logView.textColor       = [UIColor colorWithRed:0.60f green:0.90f blue:0.60f alpha:1.0f];
    _logView.font            = [UIFont fontWithName:@"Courier" size:12.0f]
                                  ?: [UIFont systemFontOfSize:12.0f];
    _logView.editable                       = NO;
    _logView.contentInset                   = UIEdgeInsetsMake(6, 8, 6, 8);
    /* Start with scroll off; _appendLog: enables it only when content overflows */
    _logView.scrollEnabled                  = NO;
    _logView.showsHorizontalScrollIndicator = NO;
    _logView.showsVerticalScrollIndicator   = YES;
    if ([_logView respondsToSelector:@selector(setAlwaysBounceHorizontal:)])
        [_logView setAlwaysBounceHorizontal:NO];
    if ([_logView respondsToSelector:@selector(setAlwaysBounceVertical:)])
        [_logView setAlwaysBounceVertical:NO];
    [_panelView addSubview:_logView];

    [self addSubview:_panelView];
    [parent addSubview:self];

    /* ── Slide-up animation (iOS 2+ UIView animation API) ──────────────── */
    CGRect finalFrame = CGRectMake(0, panelY, w, panelH);
    [UIView beginAnimations:@"SFPUploadPanelShow" context:NULL];
    [UIView setAnimationDuration:0.35];
    [UIView setAnimationCurve:UIViewAnimationCurveEaseOut];
    _panelView.frame = finalFrame;
    [UIView commitAnimations];

    /* ── Start HTTP server ──────────────────────────────────────────────── */
    BOOL ok = [_server startInDirectory:_directory startPort:8080 delegate:self];
    if (ok) {
        NSString *ip  = [SFHTTPServer localIPAddress] ?: @"0.0.0.0";
        NSString *url = [NSString stringWithFormat:@"http://%@:%u",
                         ip, (unsigned)_server.boundPort];
        [self _appendLog:url]; /* first entry: bare URL, no timestamp */
    } else {
        [self _appendLog:@"Failed to start server."];
    }
}

- (void)_appendLog:(NSString *)line {
    NSString *cur  = _logView.text ?: @"";
    NSString *next = (cur.length > 0)
                     ? [cur stringByAppendingFormat:@"\n%@", line]
                     : line;
    _logView.text = next;

    CGFloat frameW = _logView.frame.size.width;
    CGFloat frameH = _logView.frame.size.height;

    /*
     * Use sizeThatFits: (UIView, iOS 2+) to measure the natural text height
     * at the current width.  This is more reliable than contentSize when
     * scrollEnabled = NO because UITextView doesn't always update contentSize
     * while scroll is disabled.
     */
    CGSize fit = [_logView sizeThatFits:CGSizeMake(frameW, 9999.0f)];
    BOOL overflows = (fit.height > frameH);

    /* Enable vertical scroll only when text actually exceeds the view height */
    _logView.scrollEnabled = overflows;

    if (overflows) {
        /* Clamp content width — prevents any horizontal scrolling */
        CGSize cs = _logView.contentSize;
        if (cs.width > frameW)
            _logView.contentSize = CGSizeMake(frameW, cs.height);

        /* Auto-scroll to the latest entry */
        [_logView scrollRangeToVisible:NSMakeRange(next.length > 0 ? next.length - 1 : 0, 1)];
    }
}

- (void)_closeTapped {
    [self dismissAnimated:YES];
}

- (void)dismissAnimated:(BOOL)animated {
    if (_dismissing) return;
    _dismissing = YES;
    [_server stop];
    if (animated) {
        CGFloat containerH = self.bounds.size.height;
        [UIView beginAnimations:@"SFPUploadPanelHide" context:NULL];
        [UIView setAnimationDuration:0.28];
        [UIView setAnimationCurve:UIViewAnimationCurveEaseIn];
        [UIView setAnimationDelegate:self];
        [UIView setAnimationDidStopSelector:
            @selector(_dismissAnimDone:finished:context:)];
        _panelView.frame = CGRectMake(0, containerH,
                                      _panelView.frame.size.width,
                                      _panelView.frame.size.height);
        [UIView commitAnimations];
    } else {
        [self _finishDismiss];
    }
}

- (void)_dismissAnimDone:(NSString *)animId
                finished:(NSNumber *)fin
                 context:(void *)ctx {
    [self _finishDismiss];
}

- (void)_finishDismiss {
    [self removeFromSuperview];
    if (_dismissTarget && _dismissSel)
        [_dismissTarget performSelector:_dismissSel];
}

- (void)stopAndRemove {
    /* Immediate, non-animated removal called by the owning VC. */
    _dismissing    = YES; /* prevent any in-flight animation callback */
    _dismissTarget = nil; /* owner is going away — suppress callback   */
    [_server stop];
    [self removeFromSuperview];
}

/* ── SFHTTPServerDelegate ─────────────────────────────────────────────────── */
- (void)httpServer:(SFHTTPServer *)server didLog:(NSString *)message {
    [self _appendLog:message];
}

@end
