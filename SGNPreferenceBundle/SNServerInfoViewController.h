#import <UIKit/UIKit.h>

@interface SNServerInfoViewController : UITableViewController

@property (nonatomic, assign) NSInteger profileIndex;

- (id)initWithProfileIndex:(NSInteger)index;

@end