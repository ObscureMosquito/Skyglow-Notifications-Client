#import "SNCustomizationViewController.h"
#import "SNDataManager.h"

#pragma mark - Legend cell

@interface SNLegendCell : UITableViewCell
@end

@implementation SNLegendCell {
    UIView  *_polaroidCard;
    NSArray *_swatchViews;
    NSArray *_titleLabels;
    NSArray *_detailLabels;
}

/* Layout knobs — change here, layoutSubviews picks them up automatically. */
+ (CGFloat)rowHeight        { return 40.0f; }
+ (CGFloat)topInset         { return 10.0f; }  /* cell top → card top */
+ (CGFloat)botInset         { return 12.5f; }  /* card bottom → cell bottom */
+ (CGFloat)leftMargin       { return 11.0f; }  /* cell left edge → card left edge */
+ (CGFloat)textGap          { return 9.5f; }  /* card right edge → text labels */
+ (CGFloat)cardSidePad      { return 6.5f;  }  /* horizontal padding around swatches in card */
+ (CGFloat)cardTopPad       { return 1.7f;  }  /* vertical padding above first swatch in card */
+ (CGFloat)cardBottomExtra  { return 6.5f;  }  /* polaroid-style label whitespace */
+ (NSInteger)rowCount       { return 4; }

+ (CGFloat)totalHeight {
    return [self topInset]
         + [self cardTopPad] + [self rowHeight] * [self rowCount] + [self cardBottomExtra]
         + [self botInset];
}

- (instancetype)initWithStyle:(UITableViewCellStyle)style reuseIdentifier:(NSString *)reuseIdentifier {
    if ((self = [super initWithStyle:style reuseIdentifier:reuseIdentifier])) {
        self.selectionStyle = UITableViewCellSelectionStyleNone;

        _polaroidCard = [[UIView alloc] initWithFrame:CGRectZero];
        _polaroidCard.backgroundColor = [UIColor whiteColor];
        _polaroidCard.layer.shadowColor   = [UIColor blackColor].CGColor;
        _polaroidCard.layer.shadowOffset  = CGSizeMake(0, 1);
        _polaroidCard.layer.shadowRadius  = 1.0f;
        _polaroidCard.layer.shadowOpacity = 0.22f;
        [self.contentView addSubview:_polaroidCard];
        NSArray *colors = @[
            [UIColor colorWithRed:0.20f green:0.70f blue:0.20f alpha:0.8f],
            [UIColor colorWithRed:1.00f green:0.55f blue:0.05f alpha:0.8f],
            [UIColor colorWithRed:0.85f green:0.20f blue:0.20f alpha:0.8f],
            [UIColor colorWithWhite:0.55f alpha:1.0f],
        ];
        NSArray *titles = @[ @"Connected", @"Connecting", @"Error", @"Off" ];
        NSArray *details = @[
            @"Daemon is connected, receiving pushes.",
            @"Daemon is in the process of connecting.",
            @"Daemon had an an error connecting.",
            @"Daemon disabled or stopped.",
        ];

        NSMutableArray *swatches = [NSMutableArray array];
        NSMutableArray *names    = [NSMutableArray array];
        NSMutableArray *descs    = [NSMutableArray array];

        for (NSUInteger i = 0; i < colors.count; i++) {
            UIView *swatch = [[UIView alloc] initWithFrame:CGRectZero];
            swatch.backgroundColor = colors[i];
            [self.contentView addSubview:swatch];
            [swatches addObject:swatch];
            [swatch release];

            UILabel *name = [[UILabel alloc] init];
            name.text             = titles[i];
            name.font             = [UIFont boldSystemFontOfSize:14.0f];
            name.textColor        = [UIColor colorWithRed:0.18f green:0.18f blue:0.18f alpha:1.0f];
            name.shadowColor      = [UIColor colorWithWhite:1.0f alpha:0.7f];
            name.shadowOffset     = CGSizeMake(0, 1);
            name.backgroundColor  = [UIColor clearColor];
            [self.contentView addSubview:name];
            [names addObject:name];
            [name release];

            UILabel *desc = [[UILabel alloc] init];
            desc.text             = details[i];
            desc.font             = [UIFont systemFontOfSize:12.0f];
            desc.textColor        = [UIColor colorWithRed:0.40f green:0.40f blue:0.44f alpha:1.0f];
            desc.shadowColor      = [UIColor colorWithWhite:1.0f alpha:0.6f];
            desc.shadowOffset     = CGSizeMake(0, 1);
            desc.backgroundColor  = [UIColor clearColor];
            [self.contentView addSubview:desc];
            [descs addObject:desc];
            [desc release];
        }
        /* Retain the arrays for layoutSubviews; +1 each via copy. */
        _swatchViews  = [swatches copy];
        _titleLabels  = [names copy];
        _detailLabels = [descs copy];
    }
    return self;
}

- (void)dealloc {
    [_polaroidCard release];
    [_swatchViews release];
    [_titleLabels release];
    [_detailLabels release];
    [super dealloc];
}

- (void)layoutSubviews {
    [super layoutSubviews];

    CGRect b = self.contentView.bounds;
    CGFloat swatchSize  = 28.0f;
    Class   c = [self class];
    CGFloat row         = [c rowHeight];
    CGFloat top         = [c topInset];
    CGFloat leftMargin  = [c leftMargin];
    CGFloat textGap     = [c textGap];
    CGFloat sidePad     = [c cardSidePad];
    CGFloat topPad      = [c cardTopPad];
    CGFloat cardBottom  = [c cardBottomExtra];

    CGFloat swatchTopY  = top + topPad;
    CGFloat swatchColX  = leftMargin + sidePad;
    CGFloat swatchColH  = row * [c rowCount];

    _polaroidCard.frame = CGRectMake(leftMargin,
                                     top,
                                     swatchSize + sidePad * 2.0f,
                                     swatchColH + topPad + cardBottom);

    for (NSUInteger i = 0; i < _swatchViews.count; i++) {
        CGFloat rowY = swatchTopY + row * i;
        CGFloat midY = rowY + (row - swatchSize) / 2.0f;

        UIView *swatch = _swatchViews[i];
        swatch.frame = CGRectMake(swatchColX, midY, swatchSize, swatchSize);

        UILabel *name = _titleLabels[i];
        UILabel *desc = _detailLabels[i];

        CGFloat textX = CGRectGetMaxX(_polaroidCard.frame) + textGap;
        CGFloat textW = b.size.width - textX - 14.0f;

        name.frame = CGRectMake(textX, rowY + 4.0f, textW, 17.0f);
        desc.frame = CGRectMake(textX, rowY + 21.0f, textW, 15.0f);
    }
}

@end

#pragma mark - View controller

typedef enum {
    SectionIndicator = 0,
    SectionCount
} CustomizationSection;

typedef enum {
    IndicatorRowToggle = 0,
    IndicatorRowLegend = 1,
    IndicatorRowCount  = 2
} IndicatorRow;

@interface SNCustomizationViewController ()
@property (nonatomic, strong) UISwitch *indicatorSwitch;
@end

@implementation SNCustomizationViewController

/* iOS 4-5 PSRootController calls these on every pushed VC during the
 * back-pop sequence, even on plain UIViewControllers.  Crashes with
 * "unrecognized selector" otherwise. */
- (void)setRootController:(id)controller   {}
- (void)setParentController:(id)controller {}
- (void)setSpecifier:(id)specifier         {}
- (void)willResignActive                   {}
- (void)willBecomeActive                   {}

- (id)init {
    if ((self = [super initWithStyle:UITableViewStyleGrouped])) {
        self.title = @"Customization";
    }
    return self;
}

#pragma mark Data source

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return SectionCount;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return (section == SectionIndicator) ? IndicatorRowCount : 0;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (section == SectionIndicator) return @"Status Bar Indicator";
    return nil;
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == SectionIndicator)
        return @"A small coloured dot in the status bar reflecting the daemon's "
               @"live state.";
    return nil;
}

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (indexPath.section == SectionIndicator && indexPath.row == IndicatorRowLegend) {
        return [SNLegendCell totalHeight];
    }
    return 44.0f;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (indexPath.section == SectionIndicator && indexPath.row == IndicatorRowToggle) {
        UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"ToggleCell"];
        if (!cell) {
            cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                          reuseIdentifier:@"ToggleCell"];
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
            UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectZero];
            self.indicatorSwitch = sw;
            [sw release];
            [self.indicatorSwitch addTarget:self
                                     action:@selector(_indicatorSwitchChanged:)
                           forControlEvents:UIControlEventValueChanged];
            cell.accessoryView = self.indicatorSwitch;
        }
        cell.textLabel.text = @"Show in Status Bar";
        self.indicatorSwitch.on = [[SNDataManager shared] indicatorEnabled];
        return cell;
    }

    /* Legend */
    SNLegendCell *cell = [tableView dequeueReusableCellWithIdentifier:@"LegendCell"];
    if (!cell) {
        cell = [[SNLegendCell alloc] initWithStyle:UITableViewCellStyleDefault
                                   reuseIdentifier:@"LegendCell"];
    }
    return cell;
}

#pragma mark Actions

- (void)_indicatorSwitchChanged:(UISwitch *)sw {
    BOOL requestedValue = sw.on;
    if ([[SNDataManager shared] setIndicatorEnabled:requestedValue]) return;

    [self.indicatorSwitch setOn:!requestedValue animated:YES];
    UIAlertView *alert = [[UIAlertView alloc]
        initWithTitle:@"Could Not Update Skyglow"
              message:@"The status-bar setting could not be saved."
             delegate:nil
    cancelButtonTitle:@"OK"
    otherButtonTitles:nil];
    [alert show];
    [alert release];
}

- (void)dealloc {
    [_indicatorSwitch release];
    [super dealloc];
}

@end
