#import "SNCustomViewCell.h"
#import "SNLogViewController.h"
#import <UIKit/UIKit.h>

@interface SNCustomTableViewCell ()

@property (nonatomic, strong) SNLogViewController *logViewController;
@property (nonatomic, strong) UIView              *tapOverlay;

@end

@implementation SNCustomTableViewCell

+ (CGFloat)hInset           { return -50.0f; }
+ (CGFloat)vInset           { return   0.0f; }
+ (CGFloat)highlightAlpha   { return  0.18f; }
+ (NSTimeInterval)highlightDuration { return 0.18; }

- (instancetype)initWithStyle:(UITableViewCellStyle)style reuseIdentifier:(NSString *)reuseIdentifier specifier:(PSSpecifier *)specifier {
    self = [super initWithStyle:style reuseIdentifier:reuseIdentifier specifier:specifier];
    if (self) {
        self.backgroundColor             = [UIColor clearColor];
        self.contentView.backgroundColor = [UIColor clearColor];
        UIView *emptyBG = [[UIView alloc] init];
        emptyBG.backgroundColor = [UIColor clearColor];
        self.backgroundView = emptyBG;

        self.contentView.clipsToBounds = NO;
        self.clipsToBounds             = NO;

        self.logViewController = [[SNLogViewController alloc] init];
        self.logViewController.view.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        [self.contentView addSubview:self.logViewController.view];

        self.tapOverlay = [[UIView alloc] initWithFrame:self.logViewController.view.bounds];
        self.tapOverlay.autoresizingMask = UIViewAutoresizingFlexibleWidth |
                                           UIViewAutoresizingFlexibleHeight;
        self.tapOverlay.backgroundColor        = [UIColor clearColor];
        self.tapOverlay.userInteractionEnabled = NO;
        [self.logViewController.view addSubview:self.tapOverlay];

        self.selectionStyle = UITableViewCellSelectionStyleNone;
    }
    return self;
}

- (void)layoutSubviews {
    [super layoutSubviews];
    CGRect b = self.contentView.bounds;
    CGFloat hInset = [[self class] hInset];
    CGFloat vInset = [[self class] vInset];
    self.logViewController.view.frame = CGRectMake(hInset, vInset,
                                                   b.size.width  - hInset * 2.0f,
                                                   b.size.height - vInset * 2.0f);
}

- (void)setHighlighted:(BOOL)highlighted animated:(BOOL)animated {
    [super setHighlighted:highlighted animated:animated];
    [self _setOverlayTinted:highlighted animated:animated];
}

- (void)setSelected:(BOOL)selected animated:(BOOL)animated {
    [super setSelected:selected animated:animated];
    [self _setOverlayTinted:selected animated:animated];
}

- (void)_setOverlayTinted:(BOOL)tinted animated:(BOOL)animated {
    UIColor *c = tinted
        ? [UIColor colorWithWhite:0.0f alpha:[[self class] highlightAlpha]]
        : [UIColor clearColor];
    NSTimeInterval dur = animated ? [[self class] highlightDuration] : 0.0;
    [UIView animateWithDuration:dur animations:^{
        self.tapOverlay.backgroundColor = c;
    }];
}

@end
