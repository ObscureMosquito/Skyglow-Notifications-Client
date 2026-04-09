/*
 * SFPFilePicker.h
 * Compile with -fno-objc-arc.
 */

#ifndef SFP_FILE_PICKER_H
#define SFP_FILE_PICKER_H

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@interface SFPFilePickerFilter : NSObject

/* Extensions without the leading dot, e.g. @[@"plist", @"pem"] */
@property (nonatomic, retain) NSArray *allowedExtensions;

/* Exact filenames, e.g. @[@"Info.plist"] */
@property (nonatomic, retain) NSArray *allowedFilenames;

/* Absolute paths that are explicitly selectable */
@property (nonatomic, retain) NSArray *allowedPaths;

@end


@class SFPFilePickerViewController;

@protocol SFPFilePickerDelegate <NSObject>

- (void)filePicker:(SFPFilePickerViewController *)picker
didSelectFileAtPath:(NSString *)path;

@optional
- (void)filePickerDidCancel:(SFPFilePickerViewController *)picker;

@end


@interface SFPFilePickerViewController : UITableViewController

- (instancetype)initWithPath:(NSString *)path
                      filter:(SFPFilePickerFilter *)filter
                    delegate:(id<SFPFilePickerDelegate>)delegate;

+ (instancetype)pickerWithFilter:(SFPFilePickerFilter *)filter
                        delegate:(id<SFPFilePickerDelegate>)delegate;

@property (nonatomic, retain) SFPFilePickerFilter *filter;
@property (nonatomic, assign) BOOL showsHiddenFiles;
@property (nonatomic, assign) BOOL showsCancelButton;

- (void)reloadDirectory;

@end

#endif /* SFP_FILE_PICKER_H */