#import <UIKit/UIKit.h>

/* One alert/action-sheet entry point for the whole prefs bundle */
@interface SNAlert : NSObject

/* Single-button informational alert */
+ (void)presentMessage:(NSString *)message
                 title:(NSString *)title
                  from:(UIViewController *)controller;

/* Two-button confirmation */
+ (void)presentTitle:(NSString *)title
             message:(NSString *)message
        cancelButton:(NSString *)cancelTitle
       confirmButton:(NSString *)confirmTitle
         destructive:(BOOL)destructive
                from:(UIViewController *)controller
           onConfirm:(void (^)(void))onConfirm;

/* Action sheet */
+ (void)presentActionSheetTitle:(NSString *)title
                   cancelButton:(NSString *)cancelTitle
              destructiveButton:(NSString *)destructiveTitle
                   otherButtons:(NSArray *)otherTitles
                           from:(UIViewController *)controller
                     sourceView:(UIView *)sourceView
                       onSelect:(void (^)(NSString *buttonTitle))onSelect;

@end
