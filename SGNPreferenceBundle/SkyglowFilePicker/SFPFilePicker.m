/*
 * SFPFilePicker.m
 * Compile with -fno-objc-arc.
 */

#import "SFPFilePicker.h"
#import "SFPUploadViewController.h"

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

typedef enum {
    SFPFileIconEmpty = 0,
    SFPFileIconFolder,

    SFPFileIcon3GPP,
    SFPFileIconAAC,
    SFPFileIconAIFF,
    SFPFileIconBMP,
    SFPFileIconBZ2,
    SFPFileIconC,
    SFPFileIconCompressed,
    SFPFileIconConfig,
    SFPFileIconCPP,
    SFPFileIconCSS,
    SFPFileIconDiskImage,
    SFPFileIconDOC,
    SFPFileIconFlash,
    SFPFileIconGIF,
    SFPFileIconGZ,
    SFPFileIconH,
    SFPFileIconHTML,
    SFPFileIconICO,
    SFPFileIconImage,
    SFPFileIconJava,
    SFPFileIconJPEG,
    SFPFileIconJS,
    SFPFileIconKeynote,
    SFPFileIconLog,
    SFPFileIconM,
    SFPFileIconM3U,
    SFPFileIconM4R,
    SFPFileIconMP2,
    SFPFileIconMP3,
    SFPFileIconMPEG,
    SFPFileIconNumbers,
    SFPFileIconPages,
    SFPFileIconPDF,
    SFPFileIconPNG,
    SFPFileIconPPT,
    SFPFileIconRTF,
    SFPFileIconSound,
    SFPFileIconSpreadsheet,
    SFPFileIconSQLite3,
    SFPFileIconTar,
    SFPFileIconTBZ2,
    SFPFileIconText,
    SFPFileIconTGZ,
    SFPFileIconTIFF,
    SFPFileIconVideo,
    SFPFileIconWAV,
    SFPFileIconXIB,
    SFPFileIconZIP
} SFPFileIconType;

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

static UIImage *SFP_LoadBundledIconNamed(NSString *filename) {
    NSBundle *bundle = [NSBundle bundleForClass:[SFPFilePickerViewController class]];
    NSString *name = [filename stringByDeletingPathExtension];
    NSString *ext  = [filename pathExtension];

    NSString *path = [bundle pathForResource:[@"assets/" stringByAppendingString:name]
                                      ofType:ext];
    UIImage *image = [UIImage imageWithContentsOfFile:path];
    if (!image && ![filename isEqualToString:@"empty.png"]) {
        path = [bundle pathForResource:@"assets/empty" ofType:@"png"];
        image = [UIImage imageWithContentsOfFile:path];
    }
    return image;
}

static SFPFileIconType SFP_IconTypeForFilename(NSString *name, SFPItemType itemType) {
    if (itemType == SFPItemTypeSymlinkBroken) {
        return SFPFileIconEmpty;
    }
    if (itemType == SFPItemTypeDirectory || itemType == SFPItemTypeSymlinkToDirectory) {
        return SFPFileIconFolder;
    }

    NSString *ext = [[name pathExtension] lowercaseString];
    if (!ext || [ext length] == 0) {
        return SFPFileIconEmpty;
    }

    /* Exact matches first */
    if ([ext isEqualToString:@"3gpp"] || [ext isEqualToString:@"3gp"]) return SFPFileIcon3GPP;
    if ([ext isEqualToString:@"aac"])  return SFPFileIconAAC;
    if ([ext isEqualToString:@"aiff"] || [ext isEqualToString:@"aif"]) return SFPFileIconAIFF;
    if ([ext isEqualToString:@"bmp"])  return SFPFileIconBMP;
    if ([ext isEqualToString:@"bz2"])  return SFPFileIconBZ2;
    if ([ext isEqualToString:@"c"])    return SFPFileIconC;
    if ([ext isEqualToString:@"cfg"] || [ext isEqualToString:@"conf"] ||
        [ext isEqualToString:@"config"] || [ext isEqualToString:@"plist"] ||
        [ext isEqualToString:@"ini"])  return SFPFileIconConfig;
    if ([ext isEqualToString:@"cpp"] || [ext isEqualToString:@"cc"] ||
        [ext isEqualToString:@"cxx"])  return SFPFileIconCPP;
    if ([ext isEqualToString:@"css"])  return SFPFileIconCSS;
    if ([ext isEqualToString:@"dmg"] || [ext isEqualToString:@"img"] ||
        [ext isEqualToString:@"iso"])  return SFPFileIconDiskImage;
    if ([ext isEqualToString:@"doc"] || [ext isEqualToString:@"docx"]) return SFPFileIconDOC;
    if ([ext isEqualToString:@"swf"] || [ext isEqualToString:@"flv"])  return SFPFileIconFlash;
    if ([ext isEqualToString:@"gif"])  return SFPFileIconGIF;
    if ([ext isEqualToString:@"gz"])   return SFPFileIconGZ;
    if ([ext isEqualToString:@"h"])    return SFPFileIconH;
    if ([ext isEqualToString:@"htm"] || [ext isEqualToString:@"html"]) return SFPFileIconHTML;
    if ([ext isEqualToString:@"ico"] || [ext isEqualToString:@"icns"]) return SFPFileIconICO;
    if ([ext isEqualToString:@"java"]) return SFPFileIconJava;
    if ([ext isEqualToString:@"jpg"] || [ext isEqualToString:@"jpeg"]) return SFPFileIconJPEG;
    if ([ext isEqualToString:@"js"])   return SFPFileIconJS;
    if ([ext isEqualToString:@"key"] || [ext isEqualToString:@"keynote"]) return SFPFileIconKeynote;
    if ([ext isEqualToString:@"log"])  return SFPFileIconLog;
    if ([ext isEqualToString:@"m"])    return SFPFileIconM;
    if ([ext isEqualToString:@"m3u"])  return SFPFileIconM3U;
    if ([ext isEqualToString:@"m4r"])  return SFPFileIconM4R;
    if ([ext isEqualToString:@"mp2"])  return SFPFileIconMP2;
    if ([ext isEqualToString:@"mp3"])  return SFPFileIconMP3;
    if ([ext isEqualToString:@"mpeg"] || [ext isEqualToString:@"mpg"]) return SFPFileIconMPEG;
    if ([ext isEqualToString:@"numbers"]) return SFPFileIconNumbers;
    if ([ext isEqualToString:@"pages"])   return SFPFileIconPages;
    if ([ext isEqualToString:@"pdf"])  return SFPFileIconPDF;
    if ([ext isEqualToString:@"png"])  return SFPFileIconPNG;
    if ([ext isEqualToString:@"ppt"] || [ext isEqualToString:@"pptx"]) return SFPFileIconPPT;
    if ([ext isEqualToString:@"rtf"])  return SFPFileIconRTF;
    if ([ext isEqualToString:@"sqlite"] || [ext isEqualToString:@"sqlite3"] ||
        [ext isEqualToString:@"db"])   return SFPFileIconSQLite3;
    if ([ext isEqualToString:@"tar"])  return SFPFileIconTar;
    if ([ext isEqualToString:@"tbz"] || [ext isEqualToString:@"tbz2"]) return SFPFileIconTBZ2;
    if ([ext isEqualToString:@"tgz"])  return SFPFileIconTGZ;
    if ([ext isEqualToString:@"tif"] || [ext isEqualToString:@"tiff"]) return SFPFileIconTIFF;
    if ([ext isEqualToString:@"wav"])  return SFPFileIconWAV;
    if ([ext isEqualToString:@"xib"] || [ext isEqualToString:@"nib"])  return SFPFileIconXIB;
    if ([ext isEqualToString:@"zip"])  return SFPFileIconZIP;

    /* Category matches */
    if ([ext isEqualToString:@"txt"] || [ext isEqualToString:@"text"] ||
        [ext isEqualToString:@"md"]  || [ext isEqualToString:@"json"] ||
        [ext isEqualToString:@"xml"] || [ext isEqualToString:@"strings"] ||
        [ext isEqualToString:@"yaml"] || [ext isEqualToString:@"yml"] ||
        [ext isEqualToString:@"sh"]) {
        return SFPFileIconText;
    }

    if ([ext isEqualToString:@"xls"] || [ext isEqualToString:@"xlsx"] ||
        [ext isEqualToString:@"csv"] || [ext isEqualToString:@"tsv"]) {
        return SFPFileIconSpreadsheet;
    }

    if ([ext isEqualToString:@"mp4"] || [ext isEqualToString:@"mov"] ||
        [ext isEqualToString:@"m4v"] || [ext isEqualToString:@"avi"]) {
        return SFPFileIconVideo;
    }

    if ([ext isEqualToString:@"mpa"] || [ext isEqualToString:@"caf"] ||
        [ext isEqualToString:@"ogg"] || [ext isEqualToString:@"wma"]) {
        return SFPFileIconSound;
    }

    if ([ext isEqualToString:@"jpg"] || [ext isEqualToString:@"jpeg"] ||
        [ext isEqualToString:@"png"] || [ext isEqualToString:@"gif"] ||
        [ext isEqualToString:@"bmp"] || [ext isEqualToString:@"tif"] ||
        [ext isEqualToString:@"tiff"] || [ext isEqualToString:@"ico"]) {
        return SFPFileIconImage;
    }

    if ([ext isEqualToString:@"rar"] || [ext isEqualToString:@"7z"] ||
        [ext isEqualToString:@"zip"] || [ext isEqualToString:@"gz"] ||
        [ext isEqualToString:@"bz2"] || [ext isEqualToString:@"tar"] ||
        [ext isEqualToString:@"tgz"] || [ext isEqualToString:@"tbz2"]) {
        return SFPFileIconCompressed;
    }

    return SFPFileIconEmpty;
}

static NSString *SFP_IconFilenameForType(SFPFileIconType type) {
    switch (type) {
        case SFPFileIconFolder:      return @"folder.png";

        case SFPFileIcon3GPP:        return @"3gpp.png";
        case SFPFileIconAAC:         return @"aac.png";
        case SFPFileIconAIFF:        return @"aiff.png";
        case SFPFileIconBMP:         return @"bmp.png";
        case SFPFileIconBZ2:         return @"bz2.png";
        case SFPFileIconC:           return @"c.png";
        case SFPFileIconCompressed:  return @"compressed.png";
        case SFPFileIconConfig:      return @"config.png";
        case SFPFileIconCPP:         return @"cpp.png";
        case SFPFileIconCSS:         return @"css.png";
        case SFPFileIconDiskImage:   return @"diskimage.png";
        case SFPFileIconDOC:         return @"doc.png";
        case SFPFileIconFlash:       return @"flash.png";
        case SFPFileIconGIF:         return @"gif.png";
        case SFPFileIconGZ:          return @"gz.png";
        case SFPFileIconH:           return @"h.png";
        case SFPFileIconHTML:        return @"html.png";
        case SFPFileIconICO:         return @"ico.png";
        case SFPFileIconImage:       return @"image.png";
        case SFPFileIconJava:        return @"java.png";
        case SFPFileIconJPEG:        return @"jpeg.png";
        case SFPFileIconJS:          return @"js.png";
        case SFPFileIconKeynote:     return @"keynote.png";
        case SFPFileIconLog:         return @"log.png";
        case SFPFileIconM:           return @"m.png";
        case SFPFileIconM3U:         return @"m3u.png";
        case SFPFileIconM4R:         return @"m4r.png";
        case SFPFileIconMP2:         return @"mp2.png";
        case SFPFileIconMP3:         return @"mp3.png";
        case SFPFileIconMPEG:        return @"mpeg.png";
        case SFPFileIconNumbers:     return @"numbers.png";
        case SFPFileIconPages:       return @"pages.png";
        case SFPFileIconPDF:         return @"pdf.png";
        case SFPFileIconPNG:         return @"png.png";
        case SFPFileIconPPT:         return @"ppt.png";
        case SFPFileIconRTF:         return @"rtf.png";
        case SFPFileIconSound:       return @"sound.png";
        case SFPFileIconSpreadsheet: return @"spreadsheet.png";
        case SFPFileIconSQLite3:     return @"sqlite3.png";
        case SFPFileIconTar:         return @"tar.png";
        case SFPFileIconTBZ2:        return @"tbz2.png";
        case SFPFileIconText:        return @"text.png";
        case SFPFileIconTGZ:         return @"tgz.png";
        case SFPFileIconTIFF:        return @"tiff.png";
        case SFPFileIconVideo:       return @"video.png";
        case SFPFileIconWAV:         return @"wav.png";
        case SFPFileIconXIB:         return @"xib.png";
        case SFPFileIconZIP:         return @"zip.png";

        case SFPFileIconEmpty:
        default:
            return @"empty.png";
    }
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
static UIColor *SFP_DirectoryColor(void)   { return [UIColor colorWithRed:0.05f green:0.42f blue:0.86f alpha:1.0f]; }
static UIColor *SFP_GrayTextColor(void)    { return [UIColor colorWithRed:0.60f green:0.60f blue:0.60f alpha:1.0f]; }
static UIColor *SFP_ErrorTextColor(void)   { return [UIColor colorWithRed:0.82f green:0.18f blue:0.18f alpha:1.0f]; }
static UIColor *SFP_SymlinkTextColor(void) { return [UIColor colorWithRed:0.38f green:0.66f blue:0.38f alpha:1.0f]; }


/* ═══════════════════════════════════════════════════════════════════════════
 * SFPFilePickerViewController — private interface
 * ═══════════════════════════════════════════════════════════════════════════ */
@interface SFPFilePickerViewController () <UISearchBarDelegate> {
    NSString                  *_directoryPath;
    NSMutableArray            *_items;
    NSMutableArray            *_visibleItems;
    NSString                  *_searchText;
    UISearchBar               *_searchBar;
    id<SFPFilePickerDelegate>  _pickerDelegate;
    SFPFilePickerFilter       *_filter;
    BOOL                       _showsHidden;
    BOOL                       _showsCancel;
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

@end


/* ═══════════════════════════════════════════════════════════════════════════
 * SFPFilePickerViewController — implementation
 * ═══════════════════════════════════════════════════════════════════════════ */
@implementation SFPFilePickerViewController

@synthesize filter = _filter;

- (NSArray *)_displayItems {
    return (_searchText && [_searchText length] > 0) ? _visibleItems : _items;
}

- (void)_applySearchFilter {
    [_visibleItems removeAllObjects];

    NSString *query = [_searchText stringByTrimmingCharactersInSet:
                       [NSCharacterSet whitespaceAndNewlineCharacterSet]];

    if (!query || [query length] == 0) {
        [self.tableView reloadData];
        [self _updateEmptyStateView];
        return;
    }

    NSString *lowerQuery = [query lowercaseString];

    for (SFPFileItem *item in _items) {
        NSString *name = item.name ? [item.name lowercaseString] : @"";
        NSString *target = item.symlinkTarget ? [item.symlinkTarget lowercaseString] : @"";

        if ([name rangeOfString:lowerQuery].location != NSNotFound ||
            [target rangeOfString:lowerQuery].location != NSNotFound) {
            [_visibleItems addObject:item];
        }
    }

    [self.tableView reloadData];
    [self _updateEmptyStateView];
}

- (void)searchBar:(UISearchBar *)searchBar textDidChange:(NSString *)searchText {
    [_searchText release];
    _searchText = [searchText copy];
    [self _applySearchFilter];
}

- (void)searchBarSearchButtonClicked:(UISearchBar *)searchBar {
    [searchBar resignFirstResponder];
}

- (void)searchBarTextDidBeginEditing:(UISearchBar *)searchBar {
    [searchBar setShowsCancelButton:YES animated:YES];
}

- (void)searchBarTextDidEndEditing:(UISearchBar *)searchBar {
    [searchBar setShowsCancelButton:NO animated:YES];
}

- (void)searchBarCancelButtonClicked:(UISearchBar *)searchBar {
    searchBar.text = @"";

    [_searchText release];
    _searchText = nil;

    [searchBar resignFirstResponder];
    [self _applySearchFilter];
}

/* ── Lifecycle ────────────────────────────────────────────────────────────── */

- (instancetype)initWithPath:(NSString *)path
                      filter:(SFPFilePickerFilter *)filter
                    delegate:(id<SFPFilePickerDelegate>)delegate {
    self = [super initWithStyle:UITableViewStylePlain];
    if (self) {
        _directoryPath = [(path && path.length > 0 ? path : @"/var/mobile") copy];
        _filter = [filter retain];
        _pickerDelegate = delegate; /* intentionally weak */
        _showsHidden = NO;
        _showsCancel = YES;

        _items = [[NSMutableArray alloc] init];
        _visibleItems = [[NSMutableArray alloc] init];
        _searchText = nil;
        _searchBar = nil;

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
    [_directoryPath release];
    [_filter release];
    [_items release];
    [_visibleItems release];
    [_searchText release];
    [_searchBar release];
    [super dealloc];
}

/* ── UIViewController ─────────────────────────────────────────────────────── */

- (void)viewDidLoad {
    [super viewDidLoad];

    _searchBar = [[UISearchBar alloc] initWithFrame:CGRectMake(0, 0, self.tableView.bounds.size.width, 44.0f)];
    _searchBar.delegate = self;
    _searchBar.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    _searchBar.placeholder = @"Search files";
    self.tableView.tableHeaderView = _searchBar;

    [self _updateNavButtons];
    [self _updateToolbarButtons];
    [self _loadContents];
}


- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];

    NSIndexPath *sel = [self.tableView indexPathForSelectedRow];
    if (sel) [self.tableView deselectRowAtIndexPath:sel animated:animated];

    /* Show the toolbar if it isn't already visible.  Only animate the
       first appearance — navigating deeper into directories should not
       cause the toolbar to re-animate (it's already on screen). */
    if (self.navigationController.toolbarHidden) {
        [self.navigationController setToolbarHidden:NO animated:animated];
    }
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];

    UINavigationController *nav = self.navigationController;
    if (!nav) return;

    /*
     * Detect whether we are being popped (vs. just covered by a push).
     * UINavigationController removes the VC from viewControllers immediately
     * on pop, so if we're not in the array, we're being popped.
     */
    if ([nav.viewControllers containsObject:self]) return; /* covered by push — leave toolbar */

    /* We are being popped. Check if any file picker remains in the stack. */
    BOOL anyPickerRemains = NO;
    for (UIViewController *vc in nav.viewControllers) {
        if ([vc isKindOfClass:[SFPFilePickerViewController class]]) {
            anyPickerRemains = YES;
            break;
        }
    }
    if (!anyPickerRemains) {
        [nav setToolbarHidden:YES animated:animated];
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
    } else {
        self.navigationItem.leftBarButtonItem = nil;
    }
}

- (void)_updateToolbarButtons {
    NSString *toggleLabel = _showsHidden ? @"Hide Hidden" : @"Show Hidden";

    UIBarButtonItem *toggleBtn = [[UIBarButtonItem alloc]
                                  initWithTitle:toggleLabel
                                          style:UIBarButtonItemStyleBordered
                                         target:self
                                         action:@selector(_toggleHiddenFiles)];
    toggleBtn.width = 90.0f;

    UIBarButtonItem *flexSpace = [[UIBarButtonItem alloc]
                                  initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace
                                                       target:nil
                                                       action:nil];

    UIBarButtonItem *uploadBtn = [[UIBarButtonItem alloc]
                                  initWithBarButtonSystemItem:UIBarButtonSystemItemOrganize
                                                       target:self
                                                       action:@selector(_toolbarActionTapped)];

    self.toolbarItems = [NSArray arrayWithObjects:uploadBtn, flexSpace, toggleBtn, nil];

    [uploadBtn release];
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

        [self _applySearchFilter];
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

    [self _applySearchFilter];
}

/*
 * Shows a centered label when the directory is empty or nothing matches.
 * Uses tableView.backgroundView (iOS 3.2+); silently does nothing on iOS 2.
 */
- (void)_updateEmptyStateView {
    if (![self.tableView respondsToSelector:@selector(setBackgroundView:)]) return;

    if ([[self _displayItems] count] > 0) {
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
    BOOL isSearching = (_searchText && [_searchText length] > 0);
    NSString *msg = nil;

    if (isSearching) {
        msg = @"No matching files.";
    } else if (hasFilter) {
        msg = @"No matching files in this directory.";
    } else {
        msg = @"This directory is empty.";
    }

    UILabel *label = [[[UILabel alloc] init] autorelease];
    label.text = msg;
    label.textColor = SFP_GrayTextColor();
    label.font = [UIFont systemFontOfSize:15.0f];
    label.numberOfLines = 0;
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdeprecated-declarations"
    label.textAlignment = UITextAlignmentCenter;
    #pragma clang diagnostic pop
    label.backgroundColor = [UIColor clearColor];

    self.tableView.backgroundView = label;
}

/* Creates a child picker for a subdirectory, inheriting current settings. */
- (SFPFilePickerViewController *)_childPickerForPath:(NSString *)path {
    SFPFilePickerViewController *child =
        [[SFPFilePickerViewController alloc] initWithPath:path
                                                   filter:_filter
                                                 delegate:_pickerDelegate];

    /*
     * showsCancelButton MUST be set NO before showsHiddenFiles.
     * Both setters call _updateNavButtons. At init time _showsCancel = YES,
     * so if showsHiddenFiles fires first, _updateNavButtons installs a Cancel
     * button that setShowsCancelButton:NO subsequently fails to clear unless
     * _updateNavButtons explicitly nils the left item when !_showsCancel.
     */
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
    return (NSInteger)[[self _displayItems] count];
}

- (UITableViewCell *)tableView:(UITableView *)tableView
         cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString * const reuseID = @"SFPCell";

    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:reuseID];
    if (!cell) {
        /*
         * UITableViewCellStyleSubtitle gives us a title + subtitle layout.
         * The initWithStyle:reuseIdentifier: initializer arrived in iOS 3.0.
         * Fall back to the iOS 2.0 initializer when needed.
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

    NSArray *displayItems = [self _displayItems];
    SFPFileItem *item = (SFPFileItem *)[displayItems objectAtIndex:(NSUInteger)indexPath.row];
    SFPFileIconType iconType = SFP_IconTypeForFilename(item.name, item.type);
    NSString *iconFilename = SFP_IconFilenameForType(iconType);
    UIImage *iconImage = SFP_LoadBundledIconNamed(iconFilename);

    /* ── Display name ───────────────────────────────────────────────── */
    NSString *displayName = item.name;
    NSString *subtitle = nil;

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
        if (isDir) {
            cell.textLabel.text = [NSString stringWithFormat:@"%@", displayName];
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

    cell.imageView.image = iconImage;
    cell.imageView.contentMode = UIViewContentModeCenter;

    return cell;
}


/* ── UITableViewDelegate ──────────────────────────────────────────────────── */

- (void)tableView:(UITableView *)tableView
didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    NSArray *displayItems = [self _displayItems];
    SFPFileItem *item = (SFPFileItem *)[displayItems objectAtIndex:(NSUInteger)indexPath.row];

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
    return 45.0f;
}

- (CGFloat)tableView:(UITableView *)tableView
heightForHeaderInSection:(NSInteger)section {
    return 26.0f;
}

- (UIView *)tableView:(UITableView *)tableView
viewForHeaderInSection:(NSInteger)section {
    UIView *header = [[[UIView alloc] initWithFrame:CGRectMake(0, 0, tableView.bounds.size.width, 28.0f)] autorelease];

    /* Slightly translucent so scrolling rows subtly show underneath */
    header.backgroundColor = [UIColor colorWithWhite:0.9f alpha:1.0f];

    /* Top white bevel */
    UIView *topLine = [[[UIView alloc] initWithFrame:CGRectMake(0, 0.0f, tableView.bounds.size.width, 1.0f)] autorelease];
    topLine.backgroundColor = [UIColor colorWithWhite:0.65f alpha:1.0f];
    topLine.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [header addSubview:topLine];

    /* Bottom dark border (etched look) */
    UIView *bottomLine = [[[UIView alloc] initWithFrame:CGRectMake(0, 25.0f, tableView.bounds.size.width, 1.0f)] autorelease];
    bottomLine.backgroundColor = [UIColor colorWithWhite:0.65f alpha:1.0f];
    bottomLine.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [header addSubview:bottomLine];

    /* Path label */
    UILabel *label = [[[UILabel alloc] initWithFrame:CGRectMake(12.0f, 0, tableView.bounds.size.width - 24.0f, 26.0f)] autorelease];
    label.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    label.backgroundColor = [UIColor clearColor];
    label.font = [UIFont boldSystemFontOfSize:13.5f];
    label.textColor = [UIColor colorWithRed:0.29f green:0.34f blue:0.42f alpha:1.0f];
    label.shadowColor = [UIColor whiteColor];
    label.shadowOffset = CGSizeMake(0, 1.0f);
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdeprecated-declarations"
    label.lineBreakMode = UILineBreakModeTailTruncation;
    #pragma clang diagnostic pop
    label.text = _directoryPath;
    [header addSubview:label];

    return header;
}

- (void)_toolbarActionTapped {
    SFPUploadViewController *uploadVC =
        [[[SFPUploadViewController alloc] initWithDirectory:_directoryPath] autorelease];

    UINavigationController *nav =
        [[[UINavigationController alloc] initWithRootViewController:uploadVC] autorelease];



    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        if ([nav respondsToSelector:@selector(setModalPresentationStyle:)]) {
            nav.modalPresentationStyle = UIModalPresentationFormSheet;
        }
    }

    if ([nav respondsToSelector:@selector(setModalTransitionStyle:)]) {
        nav.modalTransitionStyle = UIModalTransitionStyleCoverVertical;
    }

    UIViewController *presenter = self.navigationController ?: self;

    if ([presenter respondsToSelector:@selector(presentViewController:animated:completion:)]) {
        [presenter presentViewController:nav animated:YES completion:nil];
    } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        [presenter presentModalViewController:nav animated:YES];
#pragma clang diagnostic pop
    }
}

@end