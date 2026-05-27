#ifndef SGN_UIKIT_UIStatusBarItem_H
#define SGN_UIKIT_UIStatusBarItem_H

#import <Foundation/Foundation.h>
#import <UIKit/UIView.h>

@class UIStatusBarItemView, UIStatusBarLayoutManager;

@interface UIStatusBarItem : NSObject
+ (BOOL)typeIsValid:(int)type;
+ (instancetype)itemWithType:(int)type idiom:(int)idiom;
- (instancetype)initWithType:(int)type;
- (int)type;
- (NSDictionary *)properties;
- (UIStatusBarItemView *)viewForManager:(UIStatusBarLayoutManager *)manager;
- (void)setView:(UIStatusBarItemView *)view;
@end

#endif
