#ifndef SGN_UIKIT_UIStatusBarLayoutManager_H
#define SGN_UIKIT_UIStatusBarLayoutManager_H

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

@class UIStatusBarItem, UIStatusBarItemView;

@interface UIStatusBarLayoutManager : NSObject
- (CGFloat)widthNeededForItem:(UIStatusBarItem *)item;
- (CGFloat)widthNeededForItems:(NSArray *)items;
- (CGFloat)sizeNeededForItem:(UIStatusBarItem *)item;
- (CGFloat)sizeNeededForItems:(NSArray *)items;
- (void)distributeOverlap:(CGFloat)overlap amongItems:(NSArray *)items;
- (void)clearOverlapFromItems:(NSArray *)items;
- (CGFloat)_startPosition;
- (CGRect)_frameForItemView:(UIStatusBarItemView *)view startPosition:(CGFloat)pos;
- (CGFloat)_positionAfterPlacingItemView:(UIStatusBarItemView *)view startPosition:(CGFloat)pos;
- (NSArray *)_itemViewsSortedForLayout;
@end

#endif
