/*
 * SFPFilePicker — Drop-in filesystem browser for iOS 2.0 and later.
 *
 * INTEGRATION
 * -----------
 * Add SFPFilePicker.h and SFPFilePicker.m to your project and compile with
 * -fno-objc-arc. No external dependencies beyond UIKit and Foundation.
 *
 * BASIC USAGE
 * -----------
 *   SFPFilePickerFilter *filter = [[SFPFilePickerFilter alloc] init];
 *   filter.allowedExtensions = @[@"plist", @"cert", @"pem"];
 *
 *   SFPFilePickerViewController *picker =
 *       [[SFPFilePickerViewController alloc] initWithPath:@"/var/mobile"
 *                                                  filter:filter
 *                                                delegate:self];
 *   picker.showsCancelButton = NO;           // already in a nav stack
 *   [self.navigationController pushViewController:picker animated:YES];
 *   [filter release];
 *   [picker release];
 *
 * MODAL PRESENTATION
 * ------------------
 *   SFPFilePickerViewController *picker = ...;
 *   UINavigationController *nav = [[UINavigationController alloc]
 *                                   initWithRootViewController:picker];
 *   // iOS 2–5:
 *   [self presentModalViewController:nav animated:YES];
 *   // iOS 6+:
 *   // [self presentViewController:nav animated:YES completion:nil];
 *   [nav release];
 *
 * THREADING
 * ---------
 * All methods must be called from the main thread.
 */

#ifndef SFP_FILE_PICKER_H
#define SFP_FILE_PICKER_H

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

/* ── Filter ──────────────────────────────────────────────────────────────────
 *
 * A file is selectable if it satisfies ANY populated criterion (OR logic).
 * Comparisons are case-insensitive.
 *
 * If all three arrays are nil or empty, ALL files are selectable.
 */
@interface SFPFilePickerFilter : NSObject

/** Extensions without the leading dot, e.g. @[@"plist", @"cert", @"pem"]. */
@property (nonatomic, retain) NSArray *allowedExtensions;

/** Exact filenames, e.g. @[@"Info.plist", @"manifest"]. */
@property (nonatomic, retain) NSArray *allowedFilenames;

/** Absolute paths that are explicitly selectable regardless of extension. */
@property (nonatomic, retain) NSArray *allowedPaths;

@end


/* ── Delegate ────────────────────────────────────────────────────────────── */
@class SFPFilePickerViewController;

@protocol SFPFilePickerDelegate <NSObject>

/** Called when the user taps a selectable file.
 *  The caller is responsible for dismissing or popping the picker. */
- (void)filePicker:(SFPFilePickerViewController *)picker
didSelectFileAtPath:(NSString *)path;

@optional
/** Called when the user taps the Cancel button (if shown).
 *  The caller is responsible for dismissing or popping the picker. */
- (void)filePickerDidCancel:(SFPFilePickerViewController *)picker;

@end


/* ── View Controller ─────────────────────────────────────────────────────── */
@interface SFPFilePickerViewController : UITableViewController

/**
 * Designated initialiser.
 *
 * @param path      Starting directory. Pass nil to default to /var/mobile.
 * @param filter    Selectability filter. Pass nil to allow all files.
 * @param delegate  Receives the selected path or cancel notification.
 */
- (instancetype)initWithPath:(NSString *)path
                      filter:(SFPFilePickerFilter *)filter
                    delegate:(id<SFPFilePickerDelegate>)delegate;

/** Convenience constructor that starts at /var/mobile. */
+ (instancetype)pickerWithFilter:(SFPFilePickerFilter *)filter
                        delegate:(id<SFPFilePickerDelegate>)delegate;

/**
 * The active filter. May be replaced at any time; the directory is reloaded
 * automatically. Passing nil allows all files.
 */
@property (nonatomic, retain) SFPFilePickerFilter *filter;

/**
 * Whether dotfiles (names beginning with '.') are visible.
 * Toggled by the eye button in the navigation bar.
 * Default: NO.
 */
@property (nonatomic, assign) BOOL showsHiddenFiles;

/**
 * When YES a Cancel button is shown on the left of the navigation bar.
 * Set to NO when pushing onto an existing navigation stack where the back
 * button already serves as an escape hatch.
 * Default: YES.
 */
@property (nonatomic, assign) BOOL showsCancelButton;

/** Reload the current directory listing from disk. */
- (void)reloadDirectory;

@end

#endif /* SFP_FILE_PICKER_H */
