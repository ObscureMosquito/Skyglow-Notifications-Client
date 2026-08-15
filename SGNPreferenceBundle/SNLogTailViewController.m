#import "SNLogTailViewController.h"
#import "SNLogParser.h"
#import "SNInterfaceColors.h"
#import "SNDataManager.h"
#import "SNAlert.h"
#import "SGConfiguration.h"
#import "SGSharedConstants.h"
#include <sys/stat.h>

static NSString *SNLogTailPath(void) { return SGPath(SG_LOG_PATH); }

static const NSUInteger kSNLogTailWindowBytes = 64 * 1024;
static const NSTimeInterval kSNLogTailRefreshSeconds = 1.0;
static const CGFloat kSNLogHeaderTopPad      = 10.0f;
static const CGFloat kSNLogHeaderBottomPad   = 10.0f;
static const CGFloat kSNLogSegmentHeight     = 32.0f;
static const CGFloat kSNLogSearchHeight      = 44.0f;
static const CGFloat kSNLogSegmentSideInset  = 16.0f;
static const CGFloat kSNLogControlGap        = 7.0f;
static const CGFloat kSNLogFooterTopPad      = 8.0f;
static const CGFloat kSNLogFooterHeight      = 28.0f;
static const CGFloat kSNLogFooterSideInset   = 16.0f;
static const CGFloat kSNLogMinLogRowHeight   = 220.0f;

static NSString * const kSNLogTextCellID = @"SNLogTextCell";

typedef NS_ENUM(NSInteger, SNLogContentMode) {
    SNLogContentModeTail    = 0,
    SNLogContentModeSummary = 1,
};

@interface SNLogTailViewController () <UITextViewDelegate, UIScrollViewDelegate, UISearchBarDelegate>
@property (nonatomic, strong) UITextView          *textView;
@property (nonatomic, strong) UISegmentedControl  *modeControl;
@property (nonatomic, strong) UISegmentedControl  *filterControl;
@property (nonatomic, strong) UISegmentedControl  *scopeControl;
@property (nonatomic, strong) UISearchBar         *searchBar;
@property (nonatomic, strong) UIView              *footerView;
@property (nonatomic, strong) UILabel             *footerLabel;
@property (nonatomic, strong) NSTimer             *refreshTimer;
@property (nonatomic, strong) UIBarButtonItem     *pauseItem;
@property (nonatomic, strong) UIBarButtonItem     *pasteboardItem;
@property (nonatomic, copy)   NSString            *rawTailContent;
@property (nonatomic, assign) NSUInteger           lastVisibleLineCount;
@property (nonatomic, assign) off_t                cachedSize;
@property (nonatomic, assign) time_t               cachedMTimeSec;
@property (nonatomic, assign) long                 cachedMTimeNSec;
@property (nonatomic, assign) NSInteger            cachedFilterLevel;
@property (nonatomic, assign) BOOL                 userScrolledAway;
@property (nonatomic, assign) BOOL                 paused;
@property (nonatomic, assign) SNLogFilterLevel     filterLevel;
@property (nonatomic, assign) SNLogContentMode     contentMode;
@property (nonatomic, assign) SNLogScopeFilter     scopeFilter;
@property (nonatomic, copy)   NSString            *searchText;
@end

@implementation SNLogTailViewController

- (void)setRootController:(id)controller   {}
- (void)setParentController:(id)controller {}
- (void)setSpecifier:(id)specifier         {}
- (void)willResignActive                   {}
- (void)willBecomeActive                   {}

#pragma mark - Lifecycle

- (id)init {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        self.title = @"Daemon Log";
        _filterLevel = SNLogFilterAll;
        _contentMode = SNLogContentModeTail;
        _scopeFilter = SNLogScopeAll;
        _cachedFilterLevel = -1;
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

    self.tableView.separatorStyle = UITableViewCellSeparatorStyleNone;
    self.tableView.scrollEnabled = NO;
    self.tableView.alwaysBounceHorizontal = NO;
    self.tableView.alwaysBounceVertical   = NO;
    self.tableView.showsHorizontalScrollIndicator = NO;
    self.tableView.showsVerticalScrollIndicator   = NO;

    [self setPlaceholderText:@"Loading log…"];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    self.userScrolledAway = NO;
    [self updateFooterStatus];
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];

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
    self.textView.textColor = SNSecondaryLabelColor([UIColor colorWithWhite:0.50f alpha:1.0f]);
    self.textView.text = [@"\n" stringByAppendingString:text];
    [self clampTextViewToVerticalScrolling];
}

#pragma mark - View construction

- (void)buildTableHeader {
    UISegmentedControl *mode = [[UISegmentedControl alloc]
        initWithItems:@[@"Tail", @"Summary"]];
    mode.selectedSegmentIndex = 0;
    mode.segmentedControlStyle = UISegmentedControlStyleBar;
    [mode addTarget:self
             action:@selector(modeDidChange:)
   forControlEvents:UIControlEventValueChanged];
    self.modeControl = mode;
    [mode release];

    UISegmentedControl *seg = [[UISegmentedControl alloc]
        initWithItems:@[@"All", @"Info+", @"Warn+", @"Error"]];
    seg.selectedSegmentIndex = 0;
    seg.segmentedControlStyle = UISegmentedControlStyleBar;
    [seg addTarget:self
            action:@selector(filterDidChange:)
  forControlEvents:UIControlEventValueChanged];
    self.filterControl = seg;
    [seg release];

    UISegmentedControl *scope = [[UISegmentedControl alloc]
        initWithItems:@[@"All", @"Core", @"Net", @"Push", @"Store"]];
    scope.selectedSegmentIndex = 0;
    scope.segmentedControlStyle = UISegmentedControlStyleBar;
    [scope addTarget:self
              action:@selector(scopeDidChange:)
    forControlEvents:UIControlEventValueChanged];
    self.scopeControl = scope;
    [scope release];

    UISearchBar *search = [[UISearchBar alloc] init];
    search.delegate = self;
    search.placeholder = @"Filter code, bundle, or text";
    search.autocapitalizationType = UITextAutocapitalizationTypeNone;
    search.autocorrectionType = UITextAutocorrectionTypeNo;
    search.showsCancelButton = NO;
    self.searchBar = search;
    [search release];

    CGFloat width = self.view.bounds.size.width > 10.0f
                  ? self.view.bounds.size.width
                  : 320.0f;
    CGFloat totalH = kSNLogHeaderTopPad
                   + kSNLogSegmentHeight * 3.0f
                   + kSNLogSearchHeight
                   + kSNLogControlGap * 3.0f
                   + kSNLogHeaderBottomPad;
    UIView *header = [[UIView alloc] initWithFrame:CGRectMake(0, 0, width, totalH)];
    header.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    header.backgroundColor = [UIColor clearColor];

    CGFloat y = kSNLogHeaderTopPad;
    CGFloat controlW = width - kSNLogSegmentSideInset * 2.0f;

    self.modeControl.frame = CGRectMake(kSNLogSegmentSideInset, y, controlW, kSNLogSegmentHeight);
    self.modeControl.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [header addSubview:self.modeControl];

    y += kSNLogSegmentHeight + kSNLogControlGap;
    self.filterControl.frame = CGRectMake(kSNLogSegmentSideInset, y, controlW, kSNLogSegmentHeight);
    self.filterControl.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [header addSubview:self.filterControl];

    y += kSNLogSegmentHeight + kSNLogControlGap;
    self.scopeControl.frame = CGRectMake(kSNLogSegmentSideInset, y, controlW, kSNLogSegmentHeight);
    self.scopeControl.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [header addSubview:self.scopeControl];

    y += kSNLogSegmentHeight + kSNLogControlGap;
    self.searchBar.frame = CGRectMake(0, y, width, kSNLogSearchHeight);
    self.searchBar.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [header addSubview:self.searchBar];

    self.tableView.tableHeaderView = header;
    [header release];
}

- (void)buildTableFooter {
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
    label.textColor = SNSecondaryLabelColor([UIColor colorWithRed:0.30f green:0.34f blue:0.42f alpha:1.0f]);
    label.shadowColor = SNLegacyTextShadowColor([UIColor colorWithWhite:1.0f alpha:0.7f]);
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

    if ([self.navigationItem respondsToSelector:@selector(setRightBarButtonItems:)]) {
        self.navigationItem.rightBarButtonItems = @[self.pasteboardItem, self.pauseItem];
    } else {
        self.navigationItem.rightBarButtonItem = self.pasteboardItem;
    }
}

#pragma mark - Refresh timer

- (void)startTimerIfNeeded {
    if (self.refreshTimer || self.paused) return;

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
    CGFloat total = tableView.bounds.size.height;
    CGFloat header = kSNLogHeaderTopPad
                   + kSNLogSegmentHeight * 3.0f
                   + kSNLogSearchHeight
                   + kSNLogControlGap * 3.0f
                   + kSNLogHeaderBottomPad;
    CGFloat reserved = header
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
    [self invalidateRenderedLogAndRefresh];
}

- (void)modeDidChange:(UISegmentedControl *)sender {
    self.contentMode = (SNLogContentMode)sender.selectedSegmentIndex;
    [self invalidateRenderedLogAndRefresh];
}

- (void)scopeDidChange:(UISegmentedControl *)sender {
    self.scopeFilter = (SNLogScopeFilter)sender.selectedSegmentIndex;
    [self invalidateRenderedLogAndRefresh];
}

- (void)invalidateRenderedLogAndRefresh {
    self.userScrolledAway = NO;
    self.cachedFilterLevel = -1;
    [self refreshLogs];
    [self updateFooterStatus];
}

- (void)searchBar:(UISearchBar *)searchBar textDidChange:(NSString *)searchText {
    self.searchText = searchText;
    [self invalidateRenderedLogAndRefresh];
}

- (void)searchBarSearchButtonClicked:(UISearchBar *)searchBar {
    [searchBar resignFirstResponder];
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
    NSString *pauseTitle = self.paused ? @"Resume Live Updates" : @"Pause Live Updates";
    UIView *anchor = [sender isKindOfClass:[UIView class]] ? (UIView *)sender : self.view;
    [SNAlert presentActionSheetTitle:@"Daemon Log"
                        cancelButton:@"Cancel"
                   destructiveButton:nil
                        otherButtons:@[@"Copy Support Bundle",
                                       @"Copy Diagnostic Summary",
                                       @"Copy Visible Text",
                                       @"Copy Raw Tail",
                                       pauseTitle]
                                from:self
                          sourceView:anchor
                            onSelect:^(NSString *buttonTitle) {
        if ([buttonTitle isEqualToString:@"Copy Support Bundle"]) {
            [self copyTextToPasteboard:[self supportBundleText] message:@"Support bundle copied to clipboard."];
        } else if ([buttonTitle isEqualToString:@"Copy Diagnostic Summary"]) {
            [self copyTextToPasteboard:[self diagnosticSummaryTextForCurrentTail] message:@"Diagnostic summary copied to clipboard."];
        } else if ([buttonTitle isEqualToString:@"Copy Visible Text"]) {
            [self copyTextToPasteboard:self.textView.text message:@"Visible log copied to clipboard."];
        } else if ([buttonTitle isEqualToString:@"Copy Raw Tail"]) {
            [self copyTextToPasteboard:self.rawTailContent message:@"Raw log tail copied to clipboard."];
        } else if ([buttonTitle isEqualToString:pauseTitle]) {
            [self togglePause:nil];
        }
    }];
}

- (void)copyTextToPasteboard:(NSString *)text message:(NSString *)message {
    if (text.length == 0) {
        [self showSilentActionAlert:@"Nothing to copy."];
        return;
    }
    [UIPasteboard generalPasteboard].string = text;
    [self showSilentActionAlert:message];
}

- (NSArray *)currentRawLines {
    NSString *raw = self.rawTailContent ?: @"";
    NSArray *lines = [raw componentsSeparatedByString:@"\n"];
    if (lines.count > 0 && [[lines lastObject] length] == 0) {
        lines = [lines subarrayWithRange:NSMakeRange(0, lines.count - 1)];
    }
    return lines;
}

- (NSString *)diagnosticSummaryTextForCurrentTail {
    return SNLogDiagnosticSummary([self currentRawLines],
                                  self.filterLevel, self.scopeFilter,
                                  self.searchText, NO, NULL);
}

- (NSString *)supportBundleText {
    SNDataManager *dm = [SNDataManager shared];
    SGStatusPayload payload = dm.latestPayload;
    NSDictionary *prefs = [dm mainPrefs];
    NSString *logPath = SNLogTailPath();
    NSDictionary *logAttrs = [[NSFileManager defaultManager] attributesOfItemAtPath:logPath error:nil];

    NSDateFormatter *fmt = [[[NSDateFormatter alloc] init] autorelease];
    [fmt setDateFormat:@"yyyy-MM-dd HH:mm:ss ZZZZ"];

    NSMutableString *out = [NSMutableString string];
    [out appendString:@"Skyglow Notifications Support Bundle\n"];
    [out appendFormat:@"generated=%@\n", [fmt stringFromDate:[NSDate date]]];
    [out appendFormat:@"device=%@ %@ model=%@\n",
                      [[UIDevice currentDevice] systemName],
                      [[UIDevice currentDevice] systemVersion],
                      [[UIDevice currentDevice] model]];

    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    NSString *version = [bundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?:
                        [bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?:
                        @"unknown";
    [out appendFormat:@"bundle_version=%@\n\n", version];

    [out appendString:@"Status\n"];
    [out appendFormat:@"state=%@\n", [dm friendlyStringForState:payload.state]];
    [out appendFormat:@"active_profile=%u\n", payload.activeProfileIndex];
    [out appendFormat:@"failures=%u\n", payload.consecutiveFailures];
    [out appendFormat:@"backoff_sec=%u\n", payload.currentBackoffSec];
    if (payload.errorDetail[0] != '\0') {
        payload.errorDetail[sizeof(payload.errorDetail) - 1] = '\0';
        [out appendFormat:@"error=%@\n", [NSString stringWithUTF8String:payload.errorDetail]];
    }

    [out appendString:@"\nConfiguration\n"];
    [out appendFormat:@"enabled=%@\n", [dm isEnabled] ? @"yes" : @"no"];
    [out appendFormat:@"server_address=%@\n", [dm serverAddress] ?: @"none"];
    [out appendFormat:@"device_address_present=%@\n", [dm deviceAddress].length ? @"yes" : @"no"];
    [out appendFormat:@"server_key_present=%@\n", [dm serverPubKeyPEM].length ? @"yes" : @"no"];
    [out appendFormat:@"registered_apps_pref_count=%lu\n",
                      (unsigned long)[[prefs objectForKey:@"appStatus"] count]];

    [out appendString:@"\nDatabase\n"];
    [out appendFormat:@"registered_tokens=%ld\n", (long)[dm registeredTokenCount]];
    [out appendFormat:@"db_size_bytes=%llu\n", [dm dbFileSize]];

    NSDictionary *dns = [dm cachedDNSForServerAddress:[dm serverAddress]];
    if (dns) {
        [out appendFormat:@"cached_dns_ip=%@\n", [dns objectForKey:@"ip"] ?: @"none"];
        [out appendFormat:@"cached_dns_port=%@\n", [dns objectForKey:@"port"] ?: @"none"];
    } else {
        [out appendString:@"cached_dns=none\n"];
    }

    [out appendString:@"\nFiles\n"];
    [out appendFormat:@"log_path=%@\n", logPath];
    [out appendFormat:@"log_size_bytes=%@\n", [logAttrs objectForKey:NSFileSize] ?: @"0"];
    [out appendFormat:@"prefs_path=%@\n", [dm mainPrefsPath]];
    [out appendFormat:@"profile_path=%@\n", [dm profilePath]];
    [out appendFormat:@"db_path=%@\n", [dm dbPath]];

    [out appendString:@"\nStructured Diagnostics\n"];
    [out appendString:[self diagnosticSummaryTextForCurrentTail]];

    NSString *raw = self.rawTailContent ?: @"";
    [out appendString:@"\n\nRaw Log Tail\n"];
    if (raw.length) {
        [out appendString:raw];
        if (![raw hasSuffix:@"\n"]) [out appendString:@"\n"];
    } else {
        [out appendString:@"Log file is empty or unreadable.\n"];
    }

    return out;
}

- (void)showSilentActionAlert:(NSString *)message {
    [SNAlert presentMessage:message title:@"Daemon Log" from:self];
}

#pragma mark - Log reading

- (NSString *)readTail {
    NSString *path = SNLogTailPath();

    NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:path];
    if (!fh) return nil;

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

- (void)refreshLogs {
    NSString *path = SNLogTailPath();

    struct stat st;
    if (stat([path fileSystemRepresentation], &st) != 0) {
        if (self.cachedSize != 0 || self.rawTailContent.length != 0) {
            self.cachedSize = 0;
            self.cachedMTimeSec = 0;
            self.cachedMTimeNSec = 0;
            self.rawTailContent = @"";
            self.lastVisibleLineCount = 0;
            self.textView.font = [UIFont systemFontOfSize:13.0f];
            self.textView.textColor = SNSecondaryLabelColor([UIColor colorWithWhite:0.50f alpha:1.0f]);
            self.textView.text = (self.contentMode == SNLogContentModeSummary)
                ? SNLogDiagnosticSummary([NSArray array], self.filterLevel,
                                         self.scopeFilter, self.searchText, YES, NULL)
                : SNLogRenderTail([NSArray array], self.filterLevel,
                                  self.scopeFilter, self.searchText, NULL);
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

    NSString *raw = [self readTail];
    self.rawTailContent = raw ?: @"";

    NSArray *lines = raw ? [raw componentsSeparatedByString:@"\n"] : @[];
    if (lines.count > 0 && [[lines lastObject] length] == 0) {
        lines = [lines subarrayWithRange:NSMakeRange(0, lines.count - 1)];
    }

    NSUInteger shown = 0;
    NSString *rendered = (self.contentMode == SNLogContentModeSummary)
        ? SNLogDiagnosticSummary(lines, self.filterLevel, self.scopeFilter,
                                 self.searchText, YES, &shown)
        : SNLogRenderTail(lines, self.filterLevel, self.scopeFilter,
                          self.searchText, &shown);

    BOOL countChanged = (shown != self.lastVisibleLineCount);
    self.lastVisibleLineCount = shown;
    self.textView.font = [UIFont fontWithName:@"Menlo" size:10.5f]
                       ?: [UIFont fontWithName:@"Courier" size:10.5f]
                       ?: [UIFont systemFontOfSize:10.5f];
    self.textView.textColor = SNLabelColor([UIColor colorWithRed:0.18f green:0.18f blue:0.20f alpha:1.0f]);
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
            ? @"Tap log to follow"
            : @"Live");

    NSString *unit = (self.contentMode == SNLogContentModeSummary) ? @"diagnostic" : @"line";
    NSString *pluralUnit = (self.contentMode == SNLogContentModeSummary) ? @"diagnostics" : @"lines";

    NSString *text;
    if (self.lastVisibleLineCount == 1) {
        text = [NSString stringWithFormat:@"1 %@ · %@", unit, state];
    } else {
        text = [NSString stringWithFormat:@"%lu %@ · %@",
                (unsigned long)self.lastVisibleLineCount, pluralUnit, state];
    }

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
    [_modeControl release];
    [_filterControl release];
    [_scopeControl release];
    [_searchBar release];
    [_footerView release];
    [_footerLabel release];
    [_refreshTimer release];
    [_pauseItem release];
    [_pasteboardItem release];
    [_rawTailContent release];
    [_searchText release];
    [super dealloc];
}

@end
