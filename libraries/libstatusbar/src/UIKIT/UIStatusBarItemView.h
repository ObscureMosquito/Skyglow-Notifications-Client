#ifndef SGN_UIKIT_UIStatusBarItemView_H
#define SGN_UIKIT_UIStatusBarItemView_H

#import <UIKit/UIView.h>

@class UIStatusBarItem, UIStatusBarLayoutManager;

@interface UIStatusBarItemView : UIView
- (UIStatusBarItem *)item;
- (void)setItem:(UIStatusBarItem *)item;
- (UIStatusBarLayoutManager *)layoutManager;
- (void)setLayoutManager:(UIStatusBarLayoutManager *)mgr;
- (void)setVisible:(BOOL)visible;
- (BOOL)visible;
@end

#endif
