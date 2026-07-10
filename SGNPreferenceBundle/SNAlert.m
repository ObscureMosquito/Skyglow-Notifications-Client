#import "SNAlert.h"
#import <objc/runtime.h>
#import <objc/message.h>

#define SN_STYLE_ACTIONSHEET 0
#define SN_STYLE_ALERT       1
#define SN_ACTION_DEFAULT    0
#define SN_ACTION_CANCEL     1
#define SN_ACTION_DESTRUCTIVE 2

@interface SNAlertProxy : NSObject <UIAlertViewDelegate, UIActionSheetDelegate> {
    void (^_confirmBlock)(void);
    void (^_selectBlock)(NSString *);
    NSInteger _cancelIndex;
}
- (id)initWithConfirm:(void (^)(void))confirm
               select:(void (^)(NSString *))select
          cancelIndex:(NSInteger)cancelIndex;
@end

@implementation SNAlertProxy

- (id)initWithConfirm:(void (^)(void))confirm
               select:(void (^)(NSString *))select
          cancelIndex:(NSInteger)cancelIndex {
    if ((self = [super init])) {
        _confirmBlock = [confirm copy];
        _selectBlock  = [select copy];
        _cancelIndex  = cancelIndex;
    }
    return self;
}

- (void)dealloc {
    [_confirmBlock release];
    [_selectBlock release];
    [super dealloc];
}

- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex {
    if (_confirmBlock && buttonIndex != _cancelIndex) _confirmBlock();
    [self autorelease];
}

- (void)actionSheet:(UIActionSheet *)actionSheet clickedButtonAtIndex:(NSInteger)buttonIndex {
    if (_selectBlock && buttonIndex != _cancelIndex && buttonIndex >= 0) {
        NSString *tapped = [actionSheet buttonTitleAtIndex:buttonIndex];
        if (tapped) _selectBlock(tapped);
    }
    [self autorelease];
}

@end

@implementation SNAlert

static BOOL SNHasAlertController(void) {
    return NSClassFromString(@"UIAlertController") != nil;
}

/* alertControllerWithTitle:message:preferredStyle: */
static id SNMakeController(NSString *title, NSString *message, NSInteger style) {
    Class cls = NSClassFromString(@"UIAlertController");
    SEL sel = NSSelectorFromString(@"alertControllerWithTitle:message:preferredStyle:");
    id (*fn)(Class, SEL, id, id, NSInteger) = (id (*)(Class, SEL, id, id, NSInteger))objc_msgSend;
    return fn(cls, sel, title, message, style);
}

/* actionWithTitle:style:handler: */
static id SNMakeAction(NSString *title, NSInteger style, void (^handler)(id)) {
    Class cls = NSClassFromString(@"UIAlertAction");
    SEL sel = NSSelectorFromString(@"actionWithTitle:style:handler:");
    id (*fn)(Class, SEL, id, NSInteger, id) = (id (*)(Class, SEL, id, NSInteger, id))objc_msgSend;
    return fn(cls, sel, title, style, handler);
}

static void SNAddAction(id controller, id action) {
    SEL sel = NSSelectorFromString(@"addAction:");
    void (*fn)(id, SEL, id) = (void (*)(id, SEL, id))objc_msgSend;
    fn(controller, sel, action);
}

static void SNAnchorPopover(id controller, UIView *sourceView) {
    if (!sourceView) return;
    SEL popSel = NSSelectorFromString(@"popoverPresentationController");
    id popover = ((id (*)(id, SEL))objc_msgSend)(controller, popSel);
    if (!popover) return;
    ((void (*)(id, SEL, id))objc_msgSend)(popover, @selector(setSourceView:), sourceView);
    ((void (*)(id, SEL, CGRect))objc_msgSend)(popover, @selector(setSourceRect:), [sourceView bounds]);
}

static void SNPresent(UIViewController *controller, id toPresent) {
    SEL sel = NSSelectorFromString(@"presentViewController:animated:completion:");
    void (*fn)(id, SEL, id, BOOL, id) = (void (*)(id, SEL, id, BOOL, id))objc_msgSend;
    fn(controller, sel, toPresent, YES, nil);
}

+ (void)presentMessage:(NSString *)message
                 title:(NSString *)title
                  from:(UIViewController *)controller {
    if (SNHasAlertController()) {
        id alert = SNMakeController(title, message, SN_STYLE_ALERT);
        SNAddAction(alert, SNMakeAction(@"OK", SN_ACTION_CANCEL, nil));
        SNPresent(controller, alert);
    } else {
        UIAlertView *av = [[UIAlertView alloc] initWithTitle:title
                                                     message:message
                                                    delegate:nil
                                           cancelButtonTitle:@"OK"
                                           otherButtonTitles:nil];
        [av show];
        [av release];
    }
}

+ (void)presentTitle:(NSString *)title
             message:(NSString *)message
        cancelButton:(NSString *)cancelTitle
       confirmButton:(NSString *)confirmTitle
         destructive:(BOOL)destructive
                from:(UIViewController *)controller
           onConfirm:(void (^)(void))onConfirm {
    if (SNHasAlertController()) {
        id alert = SNMakeController(title, message, SN_STYLE_ALERT);
        SNAddAction(alert, SNMakeAction(cancelTitle, SN_ACTION_CANCEL, nil));
        void (^copied)(void) = [onConfirm copy];
        id confirm = SNMakeAction(confirmTitle,
                                  destructive ? SN_ACTION_DESTRUCTIVE : SN_ACTION_DEFAULT,
                                  ^(id action) { if (copied) copied(); });
        [copied release];
        SNAddAction(alert, confirm);
        SNPresent(controller, alert);
    } else {
        SNAlertProxy *proxy = [[SNAlertProxy alloc] initWithConfirm:onConfirm
                                                             select:nil
                                                        cancelIndex:0];
        UIAlertView *av = [[UIAlertView alloc] initWithTitle:title
                                                     message:message
                                                    delegate:proxy
                                           cancelButtonTitle:cancelTitle
                                           otherButtonTitles:confirmTitle, nil];
        [av show];
        [av release];
    }
}

+ (void)presentActionSheetTitle:(NSString *)title
                   cancelButton:(NSString *)cancelTitle
              destructiveButton:(NSString *)destructiveTitle
                   otherButtons:(NSArray *)otherTitles
                           from:(UIViewController *)controller
                     sourceView:(UIView *)sourceView
                       onSelect:(void (^)(NSString *buttonTitle))onSelect {
    if (SNHasAlertController()) {
        id sheet = SNMakeController(title, nil, SN_STYLE_ACTIONSHEET);
        void (^copied)(NSString *) = [onSelect copy];

        if (destructiveTitle) {
            NSString *t = destructiveTitle;
            SNAddAction(sheet, SNMakeAction(t, SN_ACTION_DESTRUCTIVE,
                        ^(id action) { if (copied) copied(t); }));
        }
        for (NSString *t in otherTitles) {
            NSString *captured = t;
            SNAddAction(sheet, SNMakeAction(captured, SN_ACTION_DEFAULT,
                        ^(id action) { if (copied) copied(captured); }));
        }
        if (cancelTitle) {
            SNAddAction(sheet, SNMakeAction(cancelTitle, SN_ACTION_CANCEL, nil));
        }
        [copied release];

        SNAnchorPopover(sheet, sourceView ?: controller.view);
        SNPresent(controller, sheet);
    } else {
        NSInteger cancelIndex = cancelTitle
            ? (destructiveTitle ? 1 : 0) + (NSInteger)otherTitles.count
            : -1;
        SNAlertProxy *proxy = [[SNAlertProxy alloc] initWithConfirm:nil
                                                             select:onSelect
                                                        cancelIndex:cancelIndex];
        UIActionSheet *as = [[UIActionSheet alloc] initWithTitle:title
                                                        delegate:proxy
                                               cancelButtonTitle:nil
                                          destructiveButtonTitle:destructiveTitle
                                               otherButtonTitles:nil];
        for (NSString *t in otherTitles) [as addButtonWithTitle:t];
        if (cancelTitle) {
            as.cancelButtonIndex = [as addButtonWithTitle:cancelTitle];
        }
        [as showInView:(sourceView ?: controller.view)];
        [as release];
    }
}

@end
