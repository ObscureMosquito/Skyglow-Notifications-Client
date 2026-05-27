#import <Foundation/Foundation.h>

typedef void (^SNDeferredActivityBlock)(void);

@interface SNDeferredActivity : NSObject

+ (NSTimeInterval)defaultPresentationDelay;
+ (NSTimeInterval)defaultMinimumVisibleDuration;

- (id)initWithShowBlock:(SNDeferredActivityBlock)showBlock
              hideBlock:(SNDeferredActivityBlock)hideBlock;

- (id)initWithDelay:(NSTimeInterval)delay
minimumVisibleDuration:(NSTimeInterval)minimumVisibleDuration
          showBlock:(SNDeferredActivityBlock)showBlock
          hideBlock:(SNDeferredActivityBlock)hideBlock;

- (void)begin;
- (void)finishWithCompletion:(SNDeferredActivityBlock)completion;

@property (nonatomic, readonly, getter=isVisible) BOOL visible;

@end
