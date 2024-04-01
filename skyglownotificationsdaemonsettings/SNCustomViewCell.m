#import "SNCustomViewCell.h"
#import "SNLogViewController.h"
#import <UIKit/UIKit.h>

@interface SNCustomTableViewCell ()
@property (nonatomic, strong) UITextView *logTextView;
@end

@implementation SNCustomTableViewCell

- (instancetype)initWithStyle:(UITableViewCellStyle)style reuseIdentifier:(NSString *)reuseIdentifier specifier:(PSSpecifier *)specifier {
    self = [super initWithStyle:style reuseIdentifier:reuseIdentifier specifier:specifier];
    if (self) {
        ViewController *logViewController = [[ViewController alloc] init];
        // Assuming you've set up your ViewController's view to resize appropriately:
        logViewController.view.frame = self.contentView.bounds;
        logViewController.view.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        
        [self.contentView addSubview:logViewController.view];
    }
    return self;
}

@end