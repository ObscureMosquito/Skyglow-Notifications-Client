#import <Preferences/PSTableCell.h>
#include <UIKit/UIKit.h>

@interface SNAppToggleCell : PSTableCell

@property (nonatomic, strong) UIImageView *appIconView;
@property (nonatomic, strong) UILabel *appNameLabel;
@property (nonatomic, strong) UISwitch *toggleSwitch;
@property (nonatomic, strong) UIActivityIndicatorView *activityIndicator;

- (void)setDeletingAccessoryVisible:(BOOL)deleting;
- (void)setTogglePending:(BOOL)pending;

@end
