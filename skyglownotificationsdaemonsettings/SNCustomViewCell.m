#import "SNCustomViewCell.h"
#import "SNLogViewController.h"
#import <UIKit/UIKit.h>

@interface SNCustomTableViewCell ()

@property (nonatomic, strong) SNLogViewController *logViewController;

@end

@implementation SNCustomTableViewCell

- (instancetype)initWithStyle:(UITableViewCellStyle)style reuseIdentifier:(NSString *)reuseIdentifier specifier:(PSSpecifier *)specifier {
    self = [super initWithStyle:style reuseIdentifier:reuseIdentifier specifier:specifier];
    if (self) {
        self.logViewController = [[SNLogViewController alloc] init];
        self.logViewController.view.frame = self.contentView.bounds;
        self.logViewController.view.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        
        [self.contentView addSubview:self.logViewController.view];
    }
    return self;
}

@end
