#import <UIKit/UIKit.h>

@interface SNAlert : NSObject

+ (void)presentMessage:(NSString *)message
                 title:(NSString *)title
                  from:(UIViewController *)controller;

+ (void)presentTitle:(NSString *)title
             message:(NSString *)message
        cancelButton:(NSString *)cancelTitle
       confirmButton:(NSString *)confirmTitle
         destructive:(BOOL)destructive
                from:(UIViewController *)controller
           onConfirm:(void (^)(void))onConfirm;

+ (void)presentActionSheetTitle:(NSString *)title
                   cancelButton:(NSString *)cancelTitle
              destructiveButton:(NSString *)destructiveTitle
                   otherButtons:(NSArray *)otherTitles
                           from:(UIViewController *)controller
                     sourceView:(UIView *)sourceView
                       onSelect:(void (^)(NSString *buttonTitle))onSelect;

@end
