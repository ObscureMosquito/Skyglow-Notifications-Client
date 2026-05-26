#ifndef SFP_FILE_PICKER_H
#define SFP_FILE_PICKER_H

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@interface SFPFilePickerFilter : NSObject

/* Extensions without the leading dot, for example @[@"plist", @"pem"]. */
@property (nonatomic, retain) NSArray *allowedExtensions;

/* Exact filenames to allow, for example @[@"Info.plist"]. */
@property (nonatomic, retain) NSArray *allowedFilenames;

/* Absolute paths that should remain selectable regardless of filename. */
@property (nonatomic, retain) NSArray *allowedPaths;

@end


@class SFPFilePickerViewController;

@protocol SFPFilePickerDelegate <NSObject>

/* Called when the user picks a regular file or a symlink to a file. */
- (void)filePicker:(SFPFilePickerViewController *)picker
didSelectFileAtPath:(NSString *)path;

@optional

/* Called when the picker is dismissed through its cancel control. */
- (void)filePickerDidCancel:(SFPFilePickerViewController *)picker;

@end


@interface SFPFilePickerViewController : UITableViewController

/* Creates a picker rooted at the supplied directory. Pass nil to use /var/mobile. */
- (instancetype)initWithPath:(NSString *)path
                      filter:(SFPFilePickerFilter *)filter
                    delegate:(id<SFPFilePickerDelegate>)delegate;

/* Convenience constructor rooted at /var/mobile. */
+ (instancetype)pickerWithFilter:(SFPFilePickerFilter *)filter
                        delegate:(id<SFPFilePickerDelegate>)delegate;

/* Replaces the active selection rules and reloads the current directory. */
@property (nonatomic, retain) SFPFilePickerFilter *filter;

/* Includes entries that begin with a dot when enabled. */
@property (nonatomic, assign) BOOL showsHiddenFiles;

/* Shows a cancel control on the root picker when enabled. */
@property (nonatomic, assign) BOOL showsCancelButton;

/* Enables or hides the built-in HTTP upload action. */
@property (nonatomic, assign) BOOL allowsHTTPUpload;

/* First port the built-in HTTP upload action will try to bind. */
@property (nonatomic, assign) uint16_t httpUploadStartPort;

/* Reloads the current directory from disk. */
- (void)reloadDirectory;

@end

#endif /* SFP_FILE_PICKER_H */
