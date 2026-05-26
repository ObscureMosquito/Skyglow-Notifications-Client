#import <Preferences/PSTableCell.h>
#include <UIKit/UIKit.h>

@interface SNAppToggleCell : PSTableCell

/** App icon displayed in the leading edge of the cell. */
@property (nonatomic, strong) UIImageView *appIconView;

/** Primary label showing the app's display name. */
@property (nonatomic, strong) UILabel *appNameLabel;

/** Toggle controlling whether Skyglow handles notifications for this app. */
@property (nonatomic, strong) UISwitch *toggleSwitch;

/** Activity indicator shown while a forget request is in flight. */
@property (nonatomic, strong) UIActivityIndicatorView *activityIndicator;

- (void)setDeletingAccessoryVisible:(BOOL)deleting;

@end
