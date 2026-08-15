#import <UIKit/UIKit.h>
#import "../libraries/SFPFilePicker/include/SFPFilePicker.h"
#import "SNDeferredActivity.h"

/** Shared spine of the profile panes: identity, mode routing, and the
 * save-activity plumbing used by both the wizard and the detail view. */
@interface SNProfileControllerBase : UITableViewController <UITextFieldDelegate, SFPFilePickerDelegate>

@property (nonatomic, assign) NSInteger profileIndex;
@property (nonatomic, assign) BOOL      profileSaveInFlight;
@property (nonatomic, assign) BOOL      profileSaveRequestInFlight;
@property (nonatomic, strong) NSString *profileSaveStatusText;
@property (nonatomic, strong) SNDeferredActivity *profileSaveActivity;

/** Wizard when the profile has no server address yet, detail otherwise. */
+ (UIViewController *)profileControllerForIndex:(NSInteger)index;

- (id)initWithProfileIndex:(NSInteger)index;

- (BOOL)isRegistered;

/** Swaps self for the counterpart controller when the mode no longer matches. */
- (void)replaceWithProfileControllerForCurrentState;

- (void)presentPEMPicker;

- (BOOL)beginProfileSaveActivityWithStatusText:(NSString *)statusText;
- (void)finishProfileSaveActivityWithCompletion:(void (^)(void))completion;
- (void)sendProfileSaveWithServerAddress:(NSString *)serverAddress
                          certificatePEM:(NSString *)certificatePEM
                            failureTitle:(NSString *)failureTitle
                               onSuccess:(void (^)(void))successBlock;

- (CGFloat)heightForFooterTitle:(NSString *)title;

@end
