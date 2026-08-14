#import "SNDeferredActivity.h"

@implementation SNDeferredActivity {
    NSTimeInterval _delay;
    NSTimeInterval _minimumVisibleDuration;
    SNDeferredActivityBlock _showBlock;
    SNDeferredActivityBlock _hideBlock;
    NSDate *_visibleSince;
    BOOL _started;
    BOOL _finished;
    BOOL _visible;
}

+ (NSTimeInterval)defaultPresentationDelay {
    return 0.45;
}

+ (NSTimeInterval)defaultMinimumVisibleDuration {
    return 0.45;
}

+ (instancetype)begunActivityWithShowBlock:(SNDeferredActivityBlock)showBlock
                                 hideBlock:(SNDeferredActivityBlock)hideBlock {
    SNDeferredActivity *activity =
        [[[self alloc] initWithShowBlock:showBlock hideBlock:hideBlock] autorelease];
    [activity begin];
    return activity;
}

- (id)initWithShowBlock:(SNDeferredActivityBlock)showBlock
              hideBlock:(SNDeferredActivityBlock)hideBlock {
    return [self initWithDelay:[[self class] defaultPresentationDelay]
        minimumVisibleDuration:[[self class] defaultMinimumVisibleDuration]
                     showBlock:showBlock
                     hideBlock:hideBlock];
}

- (id)initWithDelay:(NSTimeInterval)delay
minimumVisibleDuration:(NSTimeInterval)minimumVisibleDuration
          showBlock:(SNDeferredActivityBlock)showBlock
          hideBlock:(SNDeferredActivityBlock)hideBlock {
    if ((self = [super init])) {
        _delay = delay;
        _minimumVisibleDuration = minimumVisibleDuration;
        _showBlock = [showBlock copy];
        _hideBlock = [hideBlock copy];
    }
    return self;
}

- (BOOL)isVisible {
    return _visible;
}

- (void)begin {
    if (_started) return;
    _started = YES;

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(_delay * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (_finished || _visible) return;
        _visible = YES;
        [_visibleSince release];
        _visibleSince = [[NSDate date] retain];
        if (_showBlock) _showBlock();
    });
}

- (void)finishWithCompletion:(SNDeferredActivityBlock)completion {
    [[self retain] autorelease];   /* completion may drop our last reference */
    if (_finished) return;
    _finished = YES;

    SNDeferredActivityBlock completionCopy = [completion copy];
    SNDeferredActivityBlock finishBlock = [^{
        _visible = NO;
        if (_hideBlock) _hideBlock();
        if (completionCopy) completionCopy();
        [completionCopy release];
    } copy];

    NSTimeInterval delay = 0.0;
    if (_visible && _visibleSince) {
        NSTimeInterval elapsed = [[NSDate date] timeIntervalSinceDate:_visibleSince];
        if (elapsed < _minimumVisibleDuration) {
            delay = _minimumVisibleDuration - elapsed;
        }
    }

    if (delay > 0.0) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            finishBlock();
            [finishBlock release];
        });
    } else {
        finishBlock();
        [finishBlock release];
    }
}

- (void)dealloc {
    [_showBlock release];
    [_hideBlock release];
    [_visibleSince release];
    [super dealloc];
}

@end
