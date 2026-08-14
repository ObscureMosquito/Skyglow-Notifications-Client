#import "SNPaneHeader.h"
#import "SNInterfaceColors.h"

UIView *SNPaneHeaderViewCreate(CGFloat tableWidth, UIView *iconBlock, NSString *bodyText) {
    CGFloat w = (tableWidth < 10.0f) ? 320.0f : tableWidth;

    const CGFloat topPad    = 22.0f;
    const CGFloat iconGap   = 10.0f;
    const CGFloat titleGap  = 4.0f;
    const CGFloat bodyGap   = 12.0f;
    const CGFloat botPad    = 18.0f;
    const CGFloat sideInset = 24.0f;

    CGRect blockFrame = iconBlock.frame;
    blockFrame.origin.x = (w - blockFrame.size.width) / 2.0f;
    blockFrame.origin.y = topPad;
    iconBlock.frame = blockFrame;
    iconBlock.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleRightMargin;

    UILabel *titleLabel     = [[[UILabel alloc] init] autorelease];
    titleLabel.text         = @"Skyglow Notifications";
    titleLabel.font         = [UIFont boldSystemFontOfSize:17.0f];
    titleLabel.textColor    = SNLabelColor([UIColor colorWithRed:0.18f green:0.18f blue:0.18f alpha:1.0f]);
    titleLabel.shadowColor  = SNLegacyTextShadowColor([UIColor colorWithWhite:1.0f alpha:0.7f]);
    titleLabel.shadowOffset = CGSizeMake(0, 1);
    titleLabel.textAlignment    = NSTextAlignmentCenter;
    titleLabel.backgroundColor  = [UIColor clearColor];
    titleLabel.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleRightMargin;
    [titleLabel sizeToFit];
    CGFloat titleY = topPad + blockFrame.size.height + iconGap;
    titleLabel.frame = CGRectMake((w - titleLabel.frame.size.width) / 2.0f,
                                  titleY,
                                  titleLabel.frame.size.width,
                                  titleLabel.frame.size.height);

    UILabel *bodyLabel      = [[[UILabel alloc] init] autorelease];
    bodyLabel.text          = bodyText;
    bodyLabel.font          = [UIFont systemFontOfSize:13.0f];
    bodyLabel.textColor     = SNSecondaryLabelColor([UIColor colorWithRed:0.38f green:0.38f blue:0.42f alpha:1.0f]);
    bodyLabel.shadowColor   = SNLegacyTextShadowColor([UIColor colorWithWhite:1.0f alpha:0.6f]);
    bodyLabel.shadowOffset  = CGSizeMake(0, 1);
    bodyLabel.textAlignment    = NSTextAlignmentCenter;
    bodyLabel.backgroundColor  = [UIColor clearColor];
    bodyLabel.numberOfLines    = 0;
    bodyLabel.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleRightMargin;
    CGFloat bodyY = titleY + titleLabel.frame.size.height + titleGap;
    CGSize bodyFit = [bodyLabel sizeThatFits:CGSizeMake(w - sideInset * 2.0f, 999.0f)];
    bodyLabel.frame = CGRectMake((w - bodyFit.width) / 2.0f, bodyY, bodyFit.width, bodyFit.height);

    CGFloat totalH = bodyY + bodyFit.height + bodyGap + botPad;
    UIView *header = [[[UIView alloc] initWithFrame:CGRectMake(0, 0, w, totalH)] autorelease];
    header.backgroundColor  = [UIColor clearColor];
    header.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [header addSubview:iconBlock];
    [header addSubview:titleLabel];
    [header addSubview:bodyLabel];
    return header;
}
