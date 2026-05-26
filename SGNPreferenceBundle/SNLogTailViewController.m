#import "SNLogTailViewController.h"
#import "../Skyglow-Notifications-Daemon/SGSharedConstants.h"
#include <sys/stat.h>

/**
 * The log file path mirrors the daemon's choice in main.m via SG_LOG_PATH
 * and is resolved through the same rootless-aware probe used elsewhere in
 * the bundle.  A missing file simply renders as the empty-state message.
 */
static NSString *SNLogTailPath(void) {
    static NSString *cached = nil;
    if (!cached) {
        BOOL rootless = [[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"];
        cached = rootless ? [@"/var/jb" stringByAppendingString:SG_LOG_PATH] : SG_LOG_PATH;
    }
    return cached;
}

/**
 * Tail window — large enough for diagnostic context, small enough that a
 * full re-render is bounded even on the rare ticks that hit the slow path.
 */
static const NSUInteger kSNLogTailWindowBytes = 64 * 1024;

/** Poll cadence. */
static const NSTimeInterval kSNLogTailRefreshSeconds = 1.0;

/** Steady-state heights. */
static const CGFloat kSNLogHeaderTopPad      = 10.0f;
static const CGFloat kSNLogHeaderBottomPad   = 10.0f;
static const CGFloat kSNLogSegmentHeight     = 32.0f;
static const CGFloat kSNLogSegmentSideInset  = 16.0f;
static const CGFloat kSNLogFooterTopPad      = 8.0f;
static const CGFloat kSNLogFooterHeight      = 28.0f;
static const CGFloat kSNLogFooterSideInset   = 16.0f;
static const CGFloat kSNLogMinLogRowHeight   = 220.0f;

typedef NS_ENUM(NSInteger, SNLogFilterLevel) {
    SNLogFilterAll   = 0,
    SNLogFilterInfo  = 1,   /* I, W, E (drops D, T) */
    SNLogFilterWarn  = 2,   /*    W, E */
    SNLogFilterError = 3,   /*       E */
};

static NSString * const kSNLogTextCellID = @"SNLogTextCell";

@interface SNLogTailViewController () <UITextViewDelegate, UIScrollViewDelegate>
@property (nonatomic, strong) UITextView          *textView;
@property (nonatomic, strong) UISegmentedControl  *filterControl;
@property (nonatomic, strong) UIView              *footerView;
@property (nonatomic, strong) UILabel             *footerLabel;
@property (nonatomic, strong) NSTimer             *refreshTimer;
@property (nonatomic, strong) UIBarButtonItem     *pauseItem;
@property (nonatomic, strong) UIBarButtonItem     *pasteboardItem;

/** Last-rendered raw tail, returned by Copy verbatim for bug reports. */
@property (nonatomic, copy)   NSString            *rawTailContent;

/** Tracks visible (post-filter) lines for the footer counter. */
@property (nonatomic, assign) NSUInteger           lastVisibleLineCount;

/** Skip-render gate — see refreshLogs. */
@property (nonatomic, assign) off_t                cachedSize;
@property (nonatomic, assign) time_t               cachedMTimeSec;
@property (nonatomic, assign) long                 cachedMTimeNSec;
@property (nonatomic, assign) NSInteger            cachedFilterLevel;

@property (nonatomic, assign) BOOL                 userScrolledAway;
@property (nonatomic, assign) BOOL                 paused;
@property (nonatomic, assign) SNLogFilterLevel     filterLevel;
@end

@implementation SNLogTailViewController

/* iOS 4-5 PSRootController calls these on every pushed VC during the
 * back-pop sequence, even on plain UIViewControllers.  Crashes with
 * "unrecognized selector" otherwise. */
- (void)setRootController:(id)controller   {}
- (void)setParentController:(id)controller {}
- (void)setSpecifier:(id)specifier         {}

#pragma mark - Lifecycle

- (id)init {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        self.title = @"Daemon Log";
        _filterLevel = SNLogFilterAll;
        _cachedFilterLevel = -1;   /* force first render */
        _cachedSize = (off_t)-1;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];

    [self buildTableHeader];
    [self buildTableFooter];
    [self buildTextView];
    [self buildNavItems];

    /**
     * The log cell is the only row and lives inside its standard grouped
     * background.  Separator lines would draw across the otherwise-blank
     * cell, so they are disabled.
     */
    self.tableView.separatorStyle = UITableViewCellSeparatorStyleNone;

    /**
     * Disable scrolling on the outer UITableView entirely.  Its content
     * always fits exactly (header + one cell + footer, sized in
     * heightForRowAtIndexPath:), so the only legitimate scroll target is
     * the UITextView inside the cell.  Leaving the table scrollable made
     * touches near the cell edges race between the two scroll views.
     */
    self.tableView.scrollEnabled = NO;
    self.tableView.alwaysBounceHorizontal = NO;
    self.tableView.alwaysBounceVertical   = NO;
    self.tableView.showsHorizontalScrollIndicator = NO;
    self.tableView.showsVerticalScrollIndicator   = NO;

    /* Initial placeholder so the view never appears blank before the
     * first read completes in viewDidAppear:. */
    [self setPlaceholderText:@"Loading log…"];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    self.userScrolledAway = NO;
    /* Footer text is cheap; safe to compute now so the chrome looks ready
     * even before the first read lands. */
    [self updateFooterStatus];
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    /**
     * The first read + parse + text assignment is the slowest single
     * operation in this VC's lifetime. Doing it in viewWillAppear: blocked
     * the navigation push animation, which the user perceived as "load
     * lag".  Deferring to viewDidAppear: lets the push complete cleanly;
     * the placeholder set in viewDidLoad covers the visible gap.
     */
    if (!self.refreshTimer) {
        [self refreshLogs];
        [self startTimerIfNeeded];
    }
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    [self stopTimer];
}

- (void)setPlaceholderText:(NSString *)text {
    if (text.length == 0) return;
    self.textView.font = [UIFont systemFontOfSize:13.0f];
    self.textView.textColor = [UIColor colorWithWhite:0.50f alpha:1.0f];
    self.textView.text = [@"\n" stringByAppendingString:text];
    [self clampTextViewToVerticalScrolling];
}

#pragma mark - View construction

- (void)buildTableHeader {
    /**
     * Segmented control sits naked in the table header — no cell wrapper.
     * UISegmentedControlStyleBar is deprecated in iOS 7 but still renders
     * the flatter "toolbar" appearance on iOS 6; on iOS 7+ the enum is
     * ignored and the OS draws the modern flat segmented control.  Either
     * way the result is visually lighter than the default chunky bevel.
     */
    UISegmentedControl *seg = [[UISegmentedControl alloc]
        initWithItems:@[@"All", @"Info+", @"Warn+", @"Error"]];
    seg.selectedSegmentIndex = 0;
    seg.segmentedControlStyle = UISegmentedControlStyleBar;
    [seg addTarget:self
            action:@selector(filterDidChange:)
  forControlEvents:UIControlEventValueChanged];
    self.filterControl = seg;
    [seg release];

    CGFloat width = self.view.bounds.size.width > 10.0f
                  ? self.view.bounds.size.width
                  : 320.0f;
    CGFloat totalH = kSNLogHeaderTopPad + kSNLogSegmentHeight + kSNLogHeaderBottomPad;
    UIView *header = [[UIView alloc] initWithFrame:CGRectMake(0, 0, width, totalH)];
    header.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    header.backgroundColor = [UIColor clearColor];

    self.filterControl.frame = CGRectMake(kSNLogSegmentSideInset,
                           kSNLogHeaderTopPad,
                           width - kSNLogSegmentSideInset * 2.0f,
                           kSNLogSegmentHeight);
    self.filterControl.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [header addSubview:self.filterControl];

    self.tableView.tableHeaderView = header;
    [header release];
}

- (void)buildTableFooter {
    /**
     * Custom footer view so we can update the status text in place at 1Hz
     * without calling reloadSections: (which rebuilds the cell, blows the
     * scroll position on the text view, and accounts for most of the
     * scrolling lag in the previous version).
     */
    CGFloat width = self.view.bounds.size.width > 10.0f
                  ? self.view.bounds.size.width
                  : 320.0f;
    CGFloat totalH = kSNLogFooterTopPad + kSNLogFooterHeight;
    UIView *footer = [[UIView alloc] initWithFrame:CGRectMake(0, 0, width, totalH)];
    footer.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    footer.backgroundColor = [UIColor clearColor];

    UILabel *label = [[UILabel alloc] initWithFrame:
        CGRectMake(kSNLogFooterSideInset,
                   kSNLogFooterTopPad,
                   width - kSNLogFooterSideInset * 2.0f,
                   kSNLogFooterHeight)];
    label.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    label.backgroundColor = [UIColor clearColor];
    label.font = [UIFont systemFontOfSize:13.0f];
    label.textColor = [UIColor colorWithRed:0.30f green:0.34f blue:0.42f alpha:1.0f];
    label.shadowColor = [UIColor colorWithWhite:1.0f alpha:0.7f];
    label.shadowOffset = CGSizeMake(0, 1);
    label.textAlignment = (NSTextAlignment)UITextAlignmentCenter;
    label.numberOfLines = 1;

    [footer addSubview:label];

    self.footerView = footer;
    self.footerLabel = label;
    self.tableView.tableFooterView = footer;
    [footer release];
    [label release];
}

- (void)buildTextView {
    UITextView *tv = [[UITextView alloc] init];
    self.textView = tv;
    [tv release];
    self.textView.editable        = NO;
    self.textView.scrollEnabled   = YES;
    self.textView.alwaysBounceVertical   = YES;
    self.textView.alwaysBounceHorizontal = NO;
    self.textView.showsHorizontalScrollIndicator = NO;
    self.textView.font = [UIFont fontWithName:@"Menlo" size:10.5f]
                       ?: [UIFont fontWithName:@"Courier" size:10.5f]
                       ?: [UIFont systemFontOfSize:10.5f];

    /**
     * Clear background so the cell's own (already-rounded) background view
     * shows through — that fixes the cosmetic "corner clip" issue.  The
     * text floats above whatever the grouped cell paints, instead of
     * painting its own white rectangle that ignores the cell's corner
     * radius.
     */
    self.textView.backgroundColor = [UIColor clearColor];

    UIEdgeInsets inset = UIEdgeInsetsMake(8, 6, 8, 6);
    self.textView.contentInset = inset;
    self.textView.scrollIndicatorInsets = inset;

    self.textView.delegate = self;
    self.textView.dataDetectorTypes = UIDataDetectorTypeNone;

    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc]
        initWithTarget:self action:@selector(logViewTapped:)];
    tap.cancelsTouchesInView = NO;
    [self.textView addGestureRecognizer:tap];
    [tap release];
}

- (void)buildNavItems {
    UIBarButtonItem *share = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemAction
                             target:self
                             action:@selector(presentShareSheet:)];
    self.pasteboardItem = share;
    [share release];

    UIBarButtonItem *pause = [[UIBarButtonItem alloc]
        initWithTitle:@"Pause"
                style:UIBarButtonItemStyleBordered
               target:self
               action:@selector(togglePause:)];
    self.pauseItem = pause;
    [pause release];

    /* rightBarButtonItems: (plural, takes an array) is iOS 5+.  On iOS 4
     * the navigation item only supports a single right item.  Pause is the
     * more critical control for live log viewing — share is a convenience
     * the user can still reach by copying log content elsewhere. */
    if ([self.navigationItem respondsToSelector:@selector(setRightBarButtonItems:)]) {
        self.navigationItem.rightBarButtonItems = @[self.pasteboardItem, self.pauseItem];
    } else {
        self.navigationItem.rightBarButtonItem = self.pauseItem;
    }
}

#pragma mark - Refresh timer

- (void)startTimerIfNeeded {
    if (self.refreshTimer || self.paused) return;
    /* NSRunLoopCommonModes keeps refreshes ticking during table-scroll
     * tracking; the default mode pauses the timer while the user drags. */
    self.refreshTimer = [NSTimer scheduledTimerWithTimeInterval:kSNLogTailRefreshSeconds
                                                         target:self
                                                       selector:@selector(refreshLogs)
                                                       userInfo:nil
                                                        repeats:YES];
    [[NSRunLoop mainRunLoop] addTimer:self.refreshTimer forMode:NSRunLoopCommonModes];
}

- (void)stopTimer {
    [self.refreshTimer invalidate];
    self.refreshTimer = nil;
}

#pragma mark - Table view

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return 1;
}

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    /**
     * Fill remaining vertical space.  Header/footer heights are known
     * statics; everything else (nav bar, status bar) is already excluded
     * from tableView.bounds.height by UIKit.
     */
    CGFloat total = tableView.bounds.size.height;
    CGFloat reserved = (kSNLogHeaderTopPad + kSNLogSegmentHeight + kSNLogHeaderBottomPad)
                     + (kSNLogFooterTopPad + kSNLogFooterHeight)
                     + 24.0f;  /* group margins above/below the section */
    CGFloat h = total - reserved;
    if (h < kSNLogMinLogRowHeight) h = kSNLogMinLogRowHeight;
    return h;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:kSNLogTextCellID];
    if (!cell) {
        cell = [[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                      reuseIdentifier:kSNLogTextCellID] autorelease];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        cell.contentView.backgroundColor = [UIColor clearColor];
        cell.contentView.clipsToBounds = YES;
    }
    if (self.textView.superview != cell.contentView) {
        [self.textView removeFromSuperview];
        /* Inset by 1pt so the text view never visibly touches the cell's
         * rounded edge even at the widest possible corner radius. */
        self.textView.frame = CGRectInset(cell.contentView.bounds, 1.0f, 1.0f);
        self.textView.autoresizingMask = UIViewAutoresizingFlexibleWidth
                                       | UIViewAutoresizingFlexibleHeight;
        [cell.contentView addSubview:self.textView];
    }
    [self clampTextViewToVerticalScrolling];
    return cell;
}

#pragma mark - Actions

- (void)filterDidChange:(UISegmentedControl *)sender {
    self.filterLevel = (SNLogFilterLevel)sender.selectedSegmentIndex;
    self.userScrolledAway = NO;   /* new filter → resume auto-follow */
    /* Filter change invalidates the cached render even if the file hasn't
     * moved — force the next refreshLogs through the slow path. */
    self.cachedFilterLevel = -1;
    [self refreshLogs];
    [self updateFooterStatus];
}

- (void)togglePause:(id)sender {
    self.paused = !self.paused;
    self.pauseItem.title = self.paused ? @"Resume" : @"Pause";
    if (self.paused) {
        [self stopTimer];
    } else {
        self.userScrolledAway = NO;
        [self startTimerIfNeeded];
        [self refreshLogs];
    }
    [self updateFooterStatus];
}

- (void)logViewTapped:(UITapGestureRecognizer *)gr {
    if (!self.userScrolledAway) return;
    self.userScrolledAway = NO;
    [self scrollToBottom];
    [self updateFooterStatus];
}

- (void)presentShareSheet:(id)sender {
    /**
     * Hand the raw (untrimmed) tail to the system share sheet — Copy,
     * Mail, Messages, AirDrop, Save to Files, whatever the user has
     * installed.  Bug reports want absolute timestamps and process
     * metadata, not the trimmed on-screen form.
     *
     * UIActivityViewController is iOS 6+. Older targets fall through to a
     * plain pasteboard write with an alert so the action is never silent.
     */
    NSString *raw = self.rawTailContent;
    NSString *content = (raw.length > 0) ? raw : (self.textView.text ?: @"");

    if (content.length == 0) {
        [self showSilentActionAlert:@"Log file is empty — nothing to share."];
        return;
    }

    Class activityCls = NSClassFromString(@"UIActivityViewController");
    if (activityCls) {
        id vc = [[[activityCls alloc] initWithActivityItems:@[content]
                                     applicationActivities:nil] autorelease];

        /* iPad: pin the popover to the share bar button.  iPhone presents
         * modally and ignores this entirely.  popoverPresentationController
         * is iOS 8+; on iOS 6/7 the selector is absent and the conditional
         * short-circuits.  KVC (valueForKey) is used instead of
         * performSelector to keep ARC happy under -Werror — no chance of
         * the "may cause a leak because its selector is unknown" warning. */
        if ([vc respondsToSelector:@selector(popoverPresentationController)]) {
            id popover = [vc valueForKey:@"popoverPresentationController"];
            if (popover) {
                [popover setValue:self.pasteboardItem forKey:@"barButtonItem"];
            }
        }

        [self presentViewController:vc animated:YES completion:nil];
    } else {
        /* Pre-iOS 6 fallback — pasteboard + explicit confirmation so the
         * user knows something happened. */
        [UIPasteboard generalPasteboard].string = content;
        [self showSilentActionAlert:@"Log copied to clipboard."];
    }
}

- (void)showSilentActionAlert:(NSString *)message {
    /* UIAlertView is deprecated on iOS 8+ but still functional all the
     * way down to iOS 2. */
    UIAlertView *av = [[UIAlertView alloc] initWithTitle:@"Daemon Log"
                                                 message:message
                                                delegate:nil
                                       cancelButtonTitle:@"OK"
                                       otherButtonTitles:nil];
    [av show];
    [av release];
}

#pragma mark - Filtering

- (BOOL)levelPassesFilter:(unichar)level {
    switch (self.filterLevel) {
        case SNLogFilterError: return (level == 'E');
        case SNLogFilterWarn:  return (level == 'E' || level == 'W');
        case SNLogFilterInfo:  return (level == 'E' || level == 'W' || level == 'I');
        default:               return YES;
    }
}

#pragma mark - Log reading

- (NSString *)readTail {
    NSString *path = SNLogTailPath();

    NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:path];
    if (!fh) return nil;

    /* Seek by stat'd size — we've already stat'd in refreshLogs but a
     * second call is cheap and saves passing the off_t around. */
    struct stat st;
    if (stat([path fileSystemRepresentation], &st) != 0) {
        [fh closeFile];
        return nil;
    }
    off_t size  = (off_t)st.st_size;
    off_t start = (size > (off_t)kSNLogTailWindowBytes)
                ? size - (off_t)kSNLogTailWindowBytes
                : 0;
    @try {
        [fh seekToFileOffset:(unsigned long long)start];
    } @catch (NSException *e) {
        [fh closeFile];
        return nil;
    }

    NSData *data = [fh readDataToEndOfFile];
    [fh closeFile];
    if (!data) return nil;

    NSString *raw = [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] autorelease];
    if (!raw) {
        raw = [[[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding] autorelease];
    }
    NSRange firstNewline = [raw rangeOfString:@"\n"];
    if (start > 0 && firstNewline.location != NSNotFound) {
        raw = [raw substringFromIndex:firstNewline.location + 1];
    }
    return raw;
}

/**
 * Strip the date and process-name prefix to keep the column tight.
 * Input  shape: "YYYY-MM-DD HH:MM:SS.mmm PROC[PID] L [TAG] body"
 * Output shape: "HH:MM:SS.mmm L [TAG] body"
 */
static BOOL SNLogParseLine(NSString *line, NSString **outTrimmed, unichar *outLevel) {
    NSRange firstSpace = [line rangeOfString:@" "];
    if (firstSpace.location == NSNotFound || line.length <= firstSpace.location + 1) {
        return NO;
    }
    NSString *afterDate = [line substringFromIndex:firstSpace.location + 1];

    NSRange secondSpace = [afterDate rangeOfString:@" "];
    if (secondSpace.location == NSNotFound) return NO;
    NSString *timePart = [afterDate substringToIndex:secondSpace.location];

    NSString *afterTime = [afterDate substringFromIndex:secondSpace.location + 1];
    NSRange thirdSpace = [afterTime rangeOfString:@" "];
    NSString *afterProc = (thirdSpace.location != NSNotFound)
                        ? [afterTime substringFromIndex:thirdSpace.location + 1]
                        : afterTime;

    if (afterProc.length == 0) return NO;
    if (outLevel) *outLevel = [afterProc characterAtIndex:0];
    if (outTrimmed) *outTrimmed = [NSString stringWithFormat:@"%@ %@", timePart, afterProc];
    return YES;
}

- (NSString *)stringForLines:(NSArray *)lines countOut:(NSUInteger *)countOut {
    NSMutableString *out = [NSMutableString string];
    NSUInteger shown = 0;

    for (NSString *line in lines) {
        if (line.length == 0) continue;

        NSString *trimmed = nil;
        unichar level = 0;
        BOOL parsed = SNLogParseLine(line, &trimmed, &level);

        if (parsed && ![self levelPassesFilter:level]) continue;
        if (!parsed && self.filterLevel != SNLogFilterAll) continue;

        NSString *display = parsed ? trimmed : line;
        [out appendString:display];
        [out appendString:@"\n"];
        shown++;
    }

    if (out.length == 0) {
        NSString *empty = (self.filterLevel == SNLogFilterAll)
            ? @"\nLog file is empty or has not been created yet."
            : @"\nNo matching lines in the current tail window.";
        [out appendString:empty];
    }

    if (countOut) *countOut = shown;
    return out;
}

- (void)refreshLogs {
    NSString *path = SNLogTailPath();

    /**
     * Fast path: stat the file and bail if neither size nor mtime nor the
     * active filter has changed since the last render.  This makes the
     * steady-state cost of a tick a single stat() syscall — no allocs, no
     * UI work, no scroll position perturbation.  That fixes the scroll lag.
     */
    struct stat st;
    if (stat([path fileSystemRepresentation], &st) != 0) {
        if (self.cachedSize != 0 || self.rawTailContent.length != 0) {
            self.cachedSize = 0;
            self.cachedMTimeSec = 0;
            self.cachedMTimeNSec = 0;
            self.rawTailContent = @"";
            self.lastVisibleLineCount = 0;
            self.textView.font = [UIFont systemFontOfSize:13.0f];
            self.textView.textColor = [UIColor colorWithWhite:0.50f alpha:1.0f];
            self.textView.text = [self stringForLines:[NSArray array] countOut:NULL];
            [self clampTextViewToVerticalScrolling];
            [self updateFooterStatus];
        }
        return;
    }

#if defined(_DARWIN_FEATURE_64_BIT_INODE) || defined(__DARWIN_64_BIT_INO_T)
    long mtimeNSec = (long)st.st_mtimespec.tv_nsec;
    time_t mtimeSec = st.st_mtimespec.tv_sec;
#else
    long mtimeNSec = 0;
    time_t mtimeSec = st.st_mtime;
#endif

    if (self.cachedSize == st.st_size
        && self.cachedMTimeSec  == mtimeSec
        && self.cachedMTimeNSec == mtimeNSec
        && self.cachedFilterLevel == (NSInteger)self.filterLevel) {
        return;
    }

    self.cachedSize       = st.st_size;
    self.cachedMTimeSec   = mtimeSec;
    self.cachedMTimeNSec  = mtimeNSec;
    self.cachedFilterLevel = (NSInteger)self.filterLevel;

    /* Slow path — file changed, do the full read + render. */
    NSString *raw = [self readTail];
    self.rawTailContent = raw ?: @"";

    NSArray *lines = raw ? [raw componentsSeparatedByString:@"\n"] : @[];
    if (lines.count > 0 && [[lines lastObject] length] == 0) {
        lines = [lines subarrayWithRange:NSMakeRange(0, lines.count - 1)];
    }

    NSUInteger shown = 0;
    NSString *rendered = [self stringForLines:lines countOut:&shown];

    BOOL countChanged = (shown != self.lastVisibleLineCount);
    self.lastVisibleLineCount = shown;
    self.textView.font = [UIFont fontWithName:@"Menlo" size:10.5f]
                       ?: [UIFont fontWithName:@"Courier" size:10.5f]
                       ?: [UIFont systemFontOfSize:10.5f];
    self.textView.textColor = [UIColor colorWithRed:0.18f green:0.18f blue:0.20f alpha:1.0f];
    self.textView.text = rendered;
    [self clampTextViewToVerticalScrolling];

    if (!self.userScrolledAway) {
        [self scrollToBottom];
    }

    if (countChanged) {
        [self updateFooterStatus];
    }
}

- (void)updateFooterStatus {
    NSString *state = self.paused
        ? @"Paused"
        : (self.userScrolledAway
            ? @"Scrolled back — tap log to resume follow"
            : @"Live");

    NSString *text;
    if (self.lastVisibleLineCount == 1) {
        text = [NSString stringWithFormat:@"1 line · %@", state];
    } else {
        text = [NSString stringWithFormat:@"%lu lines · %@",
                (unsigned long)self.lastVisibleLineCount, state];
    }

    /* In-place label mutation — no table reload, no flicker, no scroll
     * perturbation, no cell rebuild.  This was the second big lag source. */
    self.footerLabel.text = text;
}

- (void)scrollToBottom {
    NSUInteger len = self.textView.text.length;
    if (len == 0) return;
    [self.textView scrollRangeToVisible:NSMakeRange(len - 1, 1)];
    [self clampTextViewToVerticalScrolling];
}

- (void)clampTextViewToVerticalScrolling {
    if (!self.textView) return;

    self.textView.alwaysBounceHorizontal = NO;
    self.textView.showsHorizontalScrollIndicator = NO;

    CGPoint offset = self.textView.contentOffset;
    if (offset.x != 0.0f) {
        offset.x = 0.0f;
        self.textView.contentOffset = offset;
    }

    CGSize contentSize = self.textView.contentSize;
    CGFloat maxWidth = self.textView.bounds.size.width;
    if (maxWidth > 0.0f && contentSize.width > maxWidth) {
        contentSize.width = maxWidth;
        self.textView.contentSize = contentSize;
    }
}

#pragma mark - UIScrollViewDelegate

- (void)scrollViewDidScroll:(UIScrollView *)scrollView {
    if (scrollView != self.textView) return;
    if (scrollView.contentOffset.x != 0.0f) {
        CGPoint offset = scrollView.contentOffset;
        offset.x = 0.0f;
        scrollView.contentOffset = offset;
    }
    CGFloat distanceFromBottom =
        (scrollView.contentSize.height - scrollView.contentOffset.y) - scrollView.bounds.size.height;
    BOOL away = (distanceFromBottom > 40.0f);
    if (away != self.userScrolledAway) {
        self.userScrolledAway = away;
        [self updateFooterStatus];
    }
}

- (void)dealloc {
    [self stopTimer];

    [_textView release];
    [_filterControl release];
    [_footerView release];
    [_footerLabel release];
    [_refreshTimer release];
    [_pauseItem release];
    [_pasteboardItem release];
    [_rawTailContent release];
    [super dealloc];
}

@end
