/*
 * SFPFilePicker.m
 * Compile with -fno-objc-arc.
 */

#import "SFPFilePicker.h"
#import "SFPUploadPanel.h"

#include <sys/stat.h>   /* lstat(), stat(), S_ISLNK, S_ISDIR */
#include <unistd.h>     /* readlink()                         */
#include <limits.h>     /* PATH_MAX                           */

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal item type enum
 * ═══════════════════════════════════════════════════════════════════════════ */
typedef enum {
    SFPItemTypeFile,
    SFPItemTypeDirectory,
    SFPItemTypeSymlinkToFile,
    SFPItemTypeSymlinkToDirectory,
    SFPItemTypeSymlinkBroken,
} SFPItemType;

/* ═══════════════════════════════════════════════════════════════════════════
 * SFPFileItem — internal model object for one filesystem entry
 * ═══════════════════════════════════════════════════════════════════════════ */
@interface SFPFileItem : NSObject {
    NSString           *_name;
    NSString           *_fullPath;
    NSString           *_symlinkTarget;
    SFPItemType         _type;
    BOOL                _selectable;
    unsigned long long  _fileSize;
}
@property (nonatomic, retain) NSString           *name;
@property (nonatomic, retain) NSString           *fullPath;
@property (nonatomic, retain) NSString           *symlinkTarget; /* nil if not a link */
@property (nonatomic, assign) SFPItemType         type;
@property (nonatomic, assign) BOOL                selectable;
@property (nonatomic, assign) unsigned long long  fileSize;
@end

@implementation SFPFileItem
@synthesize name           = _name;
@synthesize fullPath       = _fullPath;
@synthesize symlinkTarget  = _symlinkTarget;
@synthesize type           = _type;
@synthesize selectable     = _selectable;
@synthesize fileSize       = _fileSize;
- (void)dealloc {
    [_name release];
    [_fullPath release];
    [_symlinkTarget release];
    [super dealloc];
}
@end


/* ═══════════════════════════════════════════════════════════════════════════
 * SFPFilePickerFilter
 * ═══════════════════════════════════════════════════════════════════════════ */
@implementation SFPFilePickerFilter
@synthesize allowedExtensions;
@synthesize allowedFilenames;
@synthesize allowedPaths;
- (void)dealloc {
    [allowedExtensions release];
    [allowedFilenames  release];
    [allowedPaths      release];
    [super dealloc];
}
@end


/* ═══════════════════════════════════════════════════════════════════════════
 * Static helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Human-readable file size. */
static NSString *SFP_FormatFileSize(unsigned long long bytes) {
    if (bytes < 1024ULL)
        return [NSString stringWithFormat:@"%llu B", bytes];
    if (bytes < 1024ULL * 1024ULL)
        return [NSString stringWithFormat:@"%.1f KB", bytes / 1024.0];
    if (bytes < 1024ULL * 1024ULL * 1024ULL)
        return [NSString stringWithFormat:@"%.1f MB", bytes / (1024.0 * 1024.0)];
    return [NSString stringWithFormat:@"%.1f GB", bytes / (1024.0 * 1024.0 * 1024.0)];
}

/*
 * Returns YES if fullPath/name satisfies the filter.
 * Nil filter or all-empty filter → all files match.
 */
static BOOL SFP_IsSelectable(NSString *fullPath,
                              NSString *name,
                              SFPFilePickerFilter *filter) {
    if (!filter) return YES;

    BOOL hasExt   = (filter.allowedExtensions.count > 0);
    BOOL hasNames = (filter.allowedFilenames.count  > 0);
    BOOL hasPaths = (filter.allowedPaths.count      > 0);

    if (!hasExt && !hasNames && !hasPaths) return YES;  /* unrestricted */

    if (hasExt) {
        NSString *ext = [[name pathExtension] lowercaseString];
        for (NSString *allowed in filter.allowedExtensions) {
            if ([ext isEqualToString:[allowed lowercaseString]]) return YES;
        }
    }
    if (hasNames) {
        for (NSString *allowed in filter.allowedFilenames) {
            if ([name caseInsensitiveCompare:allowed] == NSOrderedSame) return YES;
        }
    }
    if (hasPaths) {
        for (NSString *allowed in filter.allowedPaths) {
            if ([fullPath isEqualToString:allowed]) return YES;
        }
    }
    return NO;
}

/* Sort comparator: directories before files, then case-insensitive alpha. */
static NSComparisonResult SFP_ItemComparator(id aObj, id bObj, void *ctx) {
    SFPFileItem *a = (SFPFileItem *)aObj;
    SFPFileItem *b = (SFPFileItem *)bObj;
    BOOL aDir = (a.type == SFPItemTypeDirectory || a.type == SFPItemTypeSymlinkToDirectory);
    BOOL bDir = (b.type == SFPItemTypeDirectory || b.type == SFPItemTypeSymlinkToDirectory);
    if (aDir && !bDir) return NSOrderedAscending;
    if (!aDir && bDir) return NSOrderedDescending;
    return [a.name caseInsensitiveCompare:b.name];
}

/* Text colours that survive across every iOS version. */
static UIColor *SFP_DirectoryColor(void)    { return [UIColor colorWithRed:0.05f green:0.42f blue:0.86f alpha:1.0f]; }
static UIColor *SFP_GrayTextColor(void)     { return [UIColor colorWithRed:0.6f  green:0.6f  blue:0.6f  alpha:1.0f]; }
static UIColor *SFP_ErrorTextColor(void)    { return [UIColor colorWithRed:0.82f green:0.18f blue:0.18f alpha:1.0f]; }
static UIColor *SFP_SymlinkTextColor(void)  { return [UIColor colorWithRed:0.38f green:0.66f blue:0.38f alpha:1.0f]; }


/* ═══════════════════════════════════════════════════════════════════════════
 * SFPFilePickerViewController — private interface
 * ═══════════════════════════════════════════════════════════════════════════ */
@interface SFPFilePickerViewController () {
    NSString                  *_directoryPath;
    NSMutableArray            *_items;            /* array of SFPFileItem */
    id<SFPFilePickerDelegate>  _pickerDelegate;   /* weak — caller owns */
    SFPFilePickerFilter       *_filter;
    BOOL                       _showsHidden;
    BOOL                       _showsCancel;
    SFPUploadPanel            *_uploadPanel;      /* non-nil while panel is on screen */
}

- (void)_loadContents;
- (void)_updateNavButtons;
- (void)_updateToolbarButtons;
- (void)_toggleHiddenFiles;
- (void)_cancelTapped;
- (void)_updateEmptyStateView;
- (SFPFilePickerViewController *)_childPickerForPath:(NSString *)path;
- (void)_popAfterPermissionError;
- (void)_toolbarActionTapped;
- (void)_uploadPanelDismissed;

@end


/* ═══════════════════════════════════════════════════════════════════════════
 * SFPFilePickerViewController — implementation
 * ═══════════════════════════════════════════════════════════════════════════ */
@implementation SFPFilePickerViewController

@synthesize filter = _filter;

/* ── Lifecycle ────────────────────────────────────────────────────────────── */

- (instancetype)initWithPath:(NSString *)path
                      filter:(SFPFilePickerFilter *)filter
                    delegate:(id<SFPFilePickerDelegate>)delegate {
    self = [super initWithStyle:UITableViewStylePlain];
    if (self) {
        _directoryPath  = [(path && path.length > 0 ? path : @"/var/mobile") copy];
        _filter         = [filter retain];
        _pickerDelegate = delegate; /* intentionally weak */
        _showsHidden    = NO;
        _showsCancel    = YES;
        _items          = [[NSMutableArray alloc] init];

        /* Title: last component, or "/" for the filesystem root. */
        NSString *last = [_directoryPath lastPathComponent];
        self.title = (last.length > 0 && ![last isEqualToString:@"/"]) ? last : @"/";
    }
    return self;
}

+ (instancetype)pickerWithFilter:(SFPFilePickerFilter *)filter
                        delegate:(id<SFPFilePickerDelegate>)delegate {
    return [[[self alloc] initWithPath:@"/var/mobile"
                                filter:filter
                              delegate:delegate] autorelease];
}

- (void)dealloc {
    /* Stop and detach any live upload panel before releasing it. */
    if (_uploadPanel) {
        [_uploadPanel stopAndRemove];
        [_uploadPanel release];
        _uploadPanel = nil;
    }
    [_directoryPath release];
    [_filter release];
    [_items release];
    [super dealloc];
}

/* ── UIViewController ─────────────────────────────────────────────────────── */

- (void)viewDidLoad {
    [super viewDidLoad];
    [self _updateNavButtons];
    [self _updateToolbarButtons];
    [self _loadContents];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    
    NSIndexPath *sel = [self.tableView indexPathForSelectedRow];
    if (sel) [self.tableView deselectRowAtIndexPath:sel animated:animated];

    [self.navigationController setToolbarHidden:NO animated:animated];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    [self.navigationController setToolbarHidden:YES animated:animated];
    /* If the upload panel is visible (user navigated away), stop it cleanly. */
    if (_uploadPanel) {
        [_uploadPanel stopAndRemove];
        [_uploadPanel release];
        _uploadPanel = nil;
    }
}

/* ── Public properties ────────────────────────────────────────────────────── */

- (BOOL)showsHiddenFiles { return _showsHidden; }
- (void)setShowsHiddenFiles:(BOOL)v {
    _showsHidden = v;
    [self _updateNavButtons];
    [self _loadContents];
}

- (BOOL)showsCancelButton { return _showsCancel; }
- (void)setShowsCancelButton:(BOOL)v {
    _showsCancel = v;
    [self _updateNavButtons];
}

- (void)setFilter:(SFPFilePickerFilter *)newFilter {
    if (newFilter == _filter) return;
    [newFilter retain];
    [_filter release];
    _filter = newFilter;
    [self _loadContents];
}

- (void)reloadDirectory {
    [self _loadContents];
}

/* ── Private helpers ──────────────────────────────────────────────────────── */

- (void)_updateNavButtons {
    UIBarButtonItem *refresh = [[UIBarButtonItem alloc]
                                initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh
                                                     target:self
                                                     action:@selector(reloadDirectory)];
    self.navigationItem.rightBarButtonItem = refresh;
    [refresh release];

    if (_showsCancel) {
        UIBarButtonItem *cancel = [[UIBarButtonItem alloc]
                                   initWithBarButtonSystemItem:UIBarButtonSystemItemCancel
                                                        target:self
                                                        action:@selector(_cancelTapped)];
        self.navigationItem.leftBarButtonItem = cancel;
        [cancel release];
    }
}

- (void)_updateToolbarButtons {
    UIBarButtonItem *actionBtn = [[UIBarButtonItem alloc] 
                                  initWithBarButtonSystemItem:UIBarButtonSystemItemAction 
                                  target:self 
                                  action:@selector(_toolbarActionTapped)];

    NSString *toggleLabel = _showsHidden ? @"Hide Hidden" : @"Show Hidden";
    UIBarButtonItem *toggleBtn = [[UIBarButtonItem alloc]
                                  initWithTitle:toggleLabel
                                          style:UIBarButtonItemStyleBordered
                                         target:self
                                         action:@selector(_toggleHiddenFiles)];

    toggleBtn.width = 90.0f; 

    UIBarButtonItem *flexSpace = [[UIBarButtonItem alloc]
                                  initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace
                                                       target:nil action:nil];

    UIBarButtonItem *httpServerBtn = [[UIBarButtonItem alloc]
                                        initWithBarButtonSystemItem:UIBarButtonSystemItemOrganize 
                                        target:self
                                        action:@selector(_toolbarActionTapped)];

    self.toolbarItems = @[httpServerBtn, flexSpace, toggleBtn];

    [actionBtn release];
    [httpServerBtn release];
    [toggleBtn release];
    [flexSpace release];
}

- (void)_toggleHiddenFiles {
    _showsHidden = !_showsHidden;
    [self _updateNavButtons];
    [self _updateToolbarButtons];
    [self _loadContents];
}

- (void)_cancelTapped {
    if ([_pickerDelegate respondsToSelector:@selector(filePickerDidCancel:)]) {
        [_pickerDelegate filePickerDidCancel:self];
    }
}

- (void)_popAfterPermissionError {
    [self.navigationController popViewControllerAnimated:YES];
}

- (void)_loadContents {
    [_items removeAllObjects];

    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *err = nil;
    NSArray *names = nil;

    /* Prefer the modern API; fall back to the iOS 2 API if necessary. */
    if ([fm respondsToSelector:@selector(contentsOfDirectoryAtPath:error:)]) {
        names = [fm contentsOfDirectoryAtPath:_directoryPath error:&err];
    } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        names = [fm directoryContentsAtPath:_directoryPath];
#pragma clang diagnostic pop
    }

    if (!names) {
        /* Permission denied or other I/O error — alert and pop back. */
        NSString *msg = err ? [err localizedDescription]
                            : @"Unable to read directory contents.";
        UIAlertView *alert = [[UIAlertView alloc]
                              initWithTitle:@"Access Denied"
                                    message:msg
                                   delegate:nil
                          cancelButtonTitle:@"OK"
                          otherButtonTitles:nil];
        [alert show];
        [alert release];
        /* Defer the pop so it fires after the view has fully appeared. */
        [self performSelector:@selector(_popAfterPermissionError)
                   withObject:nil
                   afterDelay:0.0];
        [self.tableView reloadData];
        [self _updateEmptyStateView];
        return;
    }

    for (NSString *name in names) {
        if (!name || name.length == 0) continue;

        /* Skip dotfiles unless the user has asked to see them. */
        if (!_showsHidden && [name hasPrefix:@"."]) continue;

        NSString *fullPath = [_directoryPath stringByAppendingPathComponent:name];

        /*
         * Use lstat() so we see the symlink itself rather than its target.
         * This lets us distinguish symlinks from regular files/dirs.
         */
        struct stat lst;
        if (lstat([fullPath fileSystemRepresentation], &lst) != 0) continue;

        SFPFileItem *item = [[SFPFileItem alloc] init];
        item.name     = name;
        item.fullPath = fullPath;

        if (S_ISLNK(lst.st_mode)) {
            /* Follow the link to find the target type. */
            struct stat tst;
            if (stat([fullPath fileSystemRepresentation], &tst) == 0) {
                item.type     = S_ISDIR(tst.st_mode)
                                    ? SFPItemTypeSymlinkToDirectory
                                    : SFPItemTypeSymlinkToFile;
                item.fileSize = (unsigned long long)tst.st_size;
            } else {
                item.type = SFPItemTypeSymlinkBroken;
            }

            /* Store the raw link target for display. */
            char buf[PATH_MAX];
            ssize_t len = readlink([fullPath fileSystemRepresentation],
                                   buf, (size_t)(sizeof(buf) - 1));
            if (len > 0) {
                buf[len] = '\0';
                NSString *target = [[NSString alloc] initWithUTF8String:buf];
                item.symlinkTarget = target;
                [target release];
            }

        } else if (S_ISDIR(lst.st_mode)) {
            item.type = SFPItemTypeDirectory;

        } else {
            item.type     = SFPItemTypeFile;
            item.fileSize = (unsigned long long)lst.st_size;
        }

        /*
         * Directories and symlinks-to-directories are always browsable but
         * never "selected" — only plain files (and symlinks to files) can be
         * the result of a selection.
         */
        BOOL canSelect = (item.type == SFPItemTypeFile ||
                          item.type == SFPItemTypeSymlinkToFile);
        item.selectable = canSelect && SFP_IsSelectable(fullPath, name, _filter);

        [_items addObject:item];
        [item release];
    }

    /* Sort: directories first, then alphabetical within each group. */
    [_items sortUsingFunction:SFP_ItemComparator context:NULL];

    [self.tableView reloadData];
    [self _updateEmptyStateView];
}

/*
 * Shows a centered label when the directory is empty or nothing matches.
 * Uses tableView.backgroundView (iOS 3.2+); silently does nothing on iOS 2.
 */
- (void)_updateEmptyStateView {
    if (![self.tableView respondsToSelector:@selector(setBackgroundView:)]) return;

    if (_items.count > 0) {
        self.tableView.backgroundView = nil;
        return;
    }

    /* When a filter is active, the real directory may have files that were
     * filtered out — tell the user that specifically rather than implying
     * the directory is physically empty. */
    BOOL hasFilter = (_filter &&
                      (_filter.allowedExtensions.count > 0 ||
                       _filter.allowedFilenames.count  > 0 ||
                       _filter.allowedPaths.count      > 0));
    NSString *msg = hasFilter ? @"No matching files in this directory."
                              : @"This directory is empty.";

    UILabel *label = [[[UILabel alloc] init] autorelease];
    label.text          = msg;
    label.textColor     = SFP_GrayTextColor();
    label.font          = [UIFont systemFontOfSize:15.0f];
    label.numberOfLines = 0;
    /* NSTextAlignmentCenter == UITextAlignmentCenter == 1 on all iOS versions. */
    label.textAlignment = (NSTextAlignment)1;
    /* Keep the background transparent so the table's own background shows. */
    label.backgroundColor = [UIColor clearColor];

    self.tableView.backgroundView = label;
}

/* Creates a child picker for a subdirectory, inheriting current settings. */
- (SFPFilePickerViewController *)_childPickerForPath:(NSString *)path {
    SFPFilePickerViewController *child =
        [[SFPFilePickerViewController alloc] initWithPath:path
                                                   filter:_filter
                                                 delegate:_pickerDelegate];
    /* showsCancelButton MUST be set NO before showsHiddenFiles.
     * Both setters call _updateNavButtons. At init time _showsCancel = YES,
     * so if showsHiddenFiles fires first, _updateNavButtons installs a Cancel
     * button that setShowsCancelButton:NO subsequently fails to clear (it only
     * does nothing when NO). Reversing the order keeps leftBarButtonItem nil. */
    child.showsCancelButton = NO;
    child.showsHiddenFiles  = _showsHidden;
    return [child autorelease];
}


/* ── UITableViewDataSource ────────────────────────────────────────────────── */

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView
 numberOfRowsInSection:(NSInteger)section {
    return (NSInteger)_items.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView
         cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString * const reuseID = @"SFPCell";

    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:reuseID];
    if (!cell) {
        /*
         * UITableViewCellStyleSubtitle gives us a title + subtitle layout.
         * The initWithStyle:reuseIdentifier: initialiser arrived in iOS 3.0.
         * Fall back to the iOS 2.0 initialiser when needed.
         */
        if ([UITableViewCell instancesRespondToSelector:
                @selector(initWithStyle:reuseIdentifier:)]) {
            cell = [[[UITableViewCell alloc]
                     initWithStyle:UITableViewCellStyleSubtitle
                   reuseIdentifier:reuseID] autorelease];
        } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            cell = [[[UITableViewCell alloc]
                     initWithFrame:CGRectZero
                   reuseIdentifier:reuseID] autorelease];
#pragma clang diagnostic pop
        }
    }

    SFPFileItem *item = (SFPFileItem *)[_items objectAtIndex:(NSUInteger)indexPath.row];

    /* ── Display name ───────────────────────────────────────────────── */
    NSString *displayName = item.name;
    NSString *subtitle    = nil;

    switch (item.type) {
        case SFPItemTypeFile:
            subtitle = SFP_FormatFileSize(item.fileSize);
            break;

        case SFPItemTypeDirectory:
            subtitle = @"Folder";
            break;

        case SFPItemTypeSymlinkToFile: {
            NSString *target = item.symlinkTarget ?: @"?";
            displayName = [NSString stringWithFormat:@"%@  \xE2\x86\x92 %@",
                           item.name, target];
            /* \xE2\x86\x92 = U+2192 RIGHTWARDS ARROW */
            subtitle = [NSString stringWithFormat:@"Symlink  %@",
                        SFP_FormatFileSize(item.fileSize)];
            break;
        }

        case SFPItemTypeSymlinkToDirectory: {
            NSString *target = item.symlinkTarget ?: @"?";
            displayName = [NSString stringWithFormat:@"%@  \xE2\x86\x92 %@",
                           item.name, target];
            subtitle = @"Symlink to Folder";
            break;
        }

        case SFPItemTypeSymlinkBroken: {
            NSString *target = item.symlinkTarget ?: @"?";
            displayName = [NSString stringWithFormat:@"%@  \xE2\x86\x92 %@ (broken)",
                           item.name, target];
            subtitle = @"Broken Symlink";
            break;
        }
    }

    /* ── Text colour ────────────────────────────────────────────────── */
    UIColor *textColor;
    UIColor *detailColor = SFP_GrayTextColor();

    switch (item.type) {
        case SFPItemTypeSymlinkBroken:
            textColor   = SFP_ErrorTextColor();
            detailColor = SFP_ErrorTextColor();
            break;
        case SFPItemTypeDirectory:
            textColor = SFP_DirectoryColor();
            break;
        case SFPItemTypeSymlinkToDirectory:
            textColor = SFP_SymlinkTextColor();
            break;
        case SFPItemTypeSymlinkToFile:
            textColor = item.selectable ? SFP_SymlinkTextColor() : SFP_GrayTextColor();
            break;
        default: /* SFPItemTypeFile */
            textColor = item.selectable ? [UIColor blackColor] : SFP_GrayTextColor();
            break;
    }

    /* ── Accessory ──────────────────────────────────────────────────── */
    BOOL isDir = (item.type == SFPItemTypeDirectory ||
                  item.type == SFPItemTypeSymlinkToDirectory);
    cell.accessoryType = isDir
        ? UITableViewCellAccessoryDisclosureIndicator
        : UITableViewCellAccessoryNone;

    /* ── Apply to cell — handle both iOS 2 and iOS 3+ APIs ──────────── */
    if ([cell respondsToSelector:@selector(textLabel)]) {
        /* iOS 3.0+ */

        if (isDir) {
            cell.textLabel.text = [NSString stringWithFormat:@"\xE2\x96\xB6 %@", displayName]; /* ▶ icon */
        } else {
            cell.textLabel.text = displayName; 
        }
        
        cell.textLabel.textColor = textColor;
        cell.textLabel.font = [UIFont boldSystemFontOfSize:17.0f];
        cell.textLabel.shadowColor = [UIColor whiteColor];
        cell.textLabel.shadowOffset = CGSizeMake(0, 1.0f);
        
        if (cell.detailTextLabel) {
            cell.detailTextLabel.text = subtitle;
            cell.detailTextLabel.textColor = detailColor;
            cell.detailTextLabel.font = [UIFont systemFontOfSize:13.0f];
            cell.detailTextLabel.shadowColor = [UIColor whiteColor];
            cell.detailTextLabel.shadowOffset = CGSizeMake(0, 1.0f);
        }
    } else {
        /* iOS 2.0 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        cell.text = displayName;
#pragma clang diagnostic pop
    }

    return cell;
}


/* ── UITableViewDelegate ──────────────────────────────────────────────────── */

- (void)tableView:(UITableView *)tableView
didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    SFPFileItem *item = (SFPFileItem *)[_items objectAtIndex:(NSUInteger)indexPath.row];

    if (item.type == SFPItemTypeDirectory ||
        item.type == SFPItemTypeSymlinkToDirectory) {
        /* Push a new picker for the subdirectory. */
        SFPFilePickerViewController *child = [self _childPickerForPath:item.fullPath];
        [self.navigationController pushViewController:child animated:YES];
        /* Leave the row selected until viewWillAppear fires on return. */

    } else if (item.selectable) {
        [tableView deselectRowAtIndexPath:indexPath animated:YES];
        [_pickerDelegate filePicker:self didSelectFileAtPath:item.fullPath];

    } else {
        /* Non-selectable file tapped — just deselect, do nothing else. */
        [tableView deselectRowAtIndexPath:indexPath animated:YES];
    }
}

- (CGFloat)tableView:(UITableView *)tableView
heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    return 48.0f;
}

- (CGFloat)tableView:(UITableView *)tableView heightForHeaderInSection:(NSInteger)section {
    return 28.0f;
}

- (UIView *)tableView:(UITableView *)tableView viewForHeaderInSection:(NSInteger)section {
    UIView *header = [[[UIView alloc] initWithFrame:CGRectMake(0, 0, tableView.bounds.size.width, 28.0f)] autorelease];
    
    /* Slightly translucent so scrolling rows subtly show underneath */
    header.backgroundColor = [UIColor colorWithWhite:0.96f alpha:0.95f];
    
    /* Top white bevel */
    UIView *topLine = [[[UIView alloc] initWithFrame:CGRectMake(0, 0, tableView.bounds.size.width, 1.0f)] autorelease];
    topLine.backgroundColor = [UIColor whiteColor];
    topLine.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [header addSubview:topLine];
    
    /* Bottom dark border (etched look) */
    UIView *bottomLine = [[[UIView alloc] initWithFrame:CGRectMake(0, 27.0f, tableView.bounds.size.width, 1.0f)] autorelease];
    bottomLine.backgroundColor = [UIColor colorWithWhite:0.65f alpha:1.0f];
    bottomLine.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [header addSubview:bottomLine];
    
    /* Path label */
    UILabel *label = [[[UILabel alloc] initWithFrame:CGRectMake(12.0f, 0, tableView.bounds.size.width - 24.0f, 28.0f)] autorelease];
    label.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    label.backgroundColor = [UIColor clearColor];
    label.font = [UIFont boldSystemFontOfSize:14.0f];
    label.textColor = [UIColor colorWithRed:0.29f green:0.34f blue:0.42f alpha:1.0f];
    label.shadowColor = [UIColor whiteColor];
    label.shadowOffset = CGSizeMake(0, 1.0f);
    label.lineBreakMode = (NSLineBreakMode)3;
    label.text = _directoryPath;
    
    [header addSubview:label];
    
    return header;
}

- (void)_toolbarActionTapped {
    /* Ignore if a panel is already on screen. */
    if (_uploadPanel) return;

    /*
     * Use the navigation controller's view rather than keyWindow so the panel
     * is constrained to the preference-bundle container — on iPad the bundle
     * may occupy only part of the screen (e.g. in a Settings split view or
     * popover), and a keyWindow-anchored panel would appear in the wrong place.
     */
    UIView *container = self.navigationController
                        ? self.navigationController.view
                        : self.view;

    _uploadPanel = [[SFPUploadPanel alloc] initWithDirectory:_directoryPath];
    [_uploadPanel setDismissTarget:self selector:@selector(_uploadPanelDismissed)];
    [_uploadPanel showInView:container];
}

- (void)_uploadPanelDismissed {
    /* Called by SFPUploadPanel after its dismiss animation completes. */
    [_uploadPanel release];
    _uploadPanel = nil;
}

@end
