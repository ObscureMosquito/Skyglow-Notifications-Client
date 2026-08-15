#import "SNProfileControllerBase.h"
#import "SNProfileWizardViewController.h"
#import "SNProfileDetailViewController.h"
#import "SNDataManager.h"
#import "SNChannelGateway.h"
#import "SNAlert.h"

@interface SFPFilePickerViewController (SkyglowPSStubs)
- (void)setRootController:(id)controller;
- (void)setParentController:(id)controller;
- (void)setSpecifier:(id)specifier;
@end

@implementation SFPFilePickerViewController (SkyglowPSStubs)
- (void)setRootController:(id)controller   {}
- (void)setParentController:(id)controller {}
- (void)setSpecifier:(id)specifier         {}
- (void)willResignActive                   {}
- (void)willBecomeActive                   {}
@end

@implementation SNProfileControllerBase

- (void)setRootController:(id)controller   {}
- (void)setParentController:(id)controller {}
- (void)setSpecifier:(id)specifier         {}
- (void)willResignActive                   {}
- (void)willBecomeActive                   {}

static BOOL SNProfileIsRegistered(NSInteger index) {
    NSString *addr = [[[SNDataManager shared] profileForIndex:index]
                         objectForKey:@"server_address"];
    return [addr length] > 0;
}

+ (UIViewController *)profileControllerForIndex:(NSInteger)index {
    Class cls = SNProfileIsRegistered(index)
        ? [SNProfileDetailViewController class]
        : [SNProfileWizardViewController class];
    return [[[cls alloc] initWithProfileIndex:index] autorelease];
}

- (id)initWithProfileIndex:(NSInteger)index {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        _profileIndex = index;
        self.title = [NSString stringWithFormat:@"Profile %ld", (long)index];
    }
    return self;
}

- (BOOL)isRegistered {
    return SNProfileIsRegistered(self.profileIndex);
}

- (void)replaceWithProfileControllerForCurrentState {
    UIViewController *replacement =
        [[self class] profileControllerForIndex:self.profileIndex];
    NSMutableArray *stack = [NSMutableArray arrayWithArray:
        self.navigationController.viewControllers];
    NSUInteger position = [stack indexOfObject:self];
    if (position == NSNotFound) return;
    [stack replaceObjectAtIndex:position withObject:replacement];
    [self.navigationController setViewControllers:stack animated:NO];
}

- (void)presentPEMPicker {
    SFPFilePickerFilter *filter = [[SFPFilePickerFilter alloc] init];
    filter.allowedExtensions = @[@"pem"];

    SFPFilePickerViewController *picker =
        [[SFPFilePickerViewController alloc] initWithPath:nil
                                                   filter:filter
                                                 delegate:self];
    picker.showsCancelButton = NO;
    [self.navigationController pushViewController:picker animated:YES];
    [picker release];
    [filter release];
}

- (BOOL)beginProfileSaveActivityWithStatusText:(NSString *)statusText {
    if (self.profileSaveRequestInFlight) return NO;
    self.profileSaveRequestInFlight = YES;
    self.profileSaveStatusText = statusText ?: @"Saving\xe2\x80\xa6";
    [self.navigationItem setHidesBackButton:YES animated:YES];
    self.tableView.allowsSelection = NO;

    self.profileSaveActivity = [SNDeferredActivity begunActivityWithShowBlock:^{
        self.profileSaveInFlight = YES;
        [self.tableView reloadData];
    } hideBlock:^{
        self.profileSaveInFlight = NO;
        [self.tableView reloadData];
    }];
    return YES;
}

- (void)finishProfileSaveActivityWithCompletion:(void (^)(void))completion {
    [self.profileSaveActivity finishWithCompletion:^{
        self.profileSaveRequestInFlight = NO;
        self.profileSaveActivity = nil;
        self.profileSaveStatusText = nil;
        [self.navigationItem setHidesBackButton:NO animated:YES];
        self.tableView.allowsSelection = YES;
        if (completion) completion();
    }];
}

- (void)sendProfileSaveWithServerAddress:(NSString *)serverAddress
                          certificatePEM:(NSString *)certificatePEM
                            failureTitle:(NSString *)failureTitle
                               onSuccess:(void (^)(void))successBlock {
    [SNChannelGateway saveProfileAtIndex:self.profileIndex
                           serverAddress:serverAddress
                          certificatePEM:certificatePEM
                              completion:^(BOOL ok, NSString *message) {
        [self finishProfileSaveActivityWithCompletion:^{
            if (!ok) {
                [SNAlert presentMessage:message ?: @"The daemon did not respond."
                                  title:failureTitle ?: @"Save Failed"
                                   from:self];
                [self.tableView reloadData];
                return;
            }
            if (successBlock) successBlock();
        }];
    }];
}

- (CGFloat)heightForFooterTitle:(NSString *)title {
    if ([title length] == 0) return 0.0f;
    CGFloat width = self.tableView.bounds.size.width;
    if (width < 10.0f) width = 320.0f;
    CGSize size = [title sizeWithFont:[UIFont systemFontOfSize:13.0f]
                    constrainedToSize:CGSizeMake(width - 32.0f, 200.0f)
                        lineBreakMode:NSLineBreakByWordWrapping];
    return size.height + 18.0f;
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    [textField resignFirstResponder];
    return YES;
}

/* Subclasses override with their own confirm/import flow. */
- (void)filePicker:(SFPFilePickerViewController *)picker
    didSelectFileAtPath:(NSString *)path {
}

- (void)dealloc {
    [_profileSaveStatusText release];
    [_profileSaveActivity release];
    [super dealloc];
}

@end
