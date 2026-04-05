#import <UIKit/UIKit.h>

@interface SNProfileListController : UITableViewController

/* Set by PreferenceLoader when navigating from Root.plist */
@property (nonatomic, strong) id rootController;
@property (nonatomic, strong) id parentController;
@property (nonatomic, strong) id specifier;

@end
