#import <Preferences/PSTableCell.h>
#include <UIKit/UIKit.h>

@interface SNAppToggleCell : PSTableCell
@property (nonatomic, strong) UIImageView *appIconView;
@property (nonatomic, strong) UILabel *appNameLabel;
@property (nonatomic, strong) UISwitch *toggleSwitch;
@end