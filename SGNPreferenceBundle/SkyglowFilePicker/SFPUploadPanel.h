/*
 * SFPUploadPanel.h — slide-up Wi-Fi file-upload overlay for SFPFilePicker.
 * Compile with -fno-objc-arc (MRC).
 *
 * Usage:
 *   SFPUploadPanel *panel = [[SFPUploadPanel alloc] initWithDirectory:path];
 *   [panel setDismissTarget:self selector:@selector(panelDismissed)];
 *   [panel showInView:[UIApplication sharedApplication].keyWindow];
 *
 *   // When the owning VC disappears before the user closes the panel:
 *   [panel stopAndRemove];
 *   [panel release];
 */

#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>

@interface SFPUploadPanel : UIView

/**
 * Designated initialiser.
 * @param dir  The directory that the HTTP server will accept uploads into.
 */
- (id)initWithDirectory:(NSString *)dir;

/**
 * Adds the panel to @p parent (typically keyWindow), starts the server, and
 * slides the panel up with animation.  The first log line shows the server URL.
 */
- (void)showInView:(UIView *)parent;

/**
 * Animates the panel down (animated=YES) or removes it instantly (animated=NO),
 * stops the server, then calls the dismiss callback.
 * Safe to call even if the panel is already being dismissed.
 */
- (void)dismissAnimated:(BOOL)animated;

/**
 * Immediately stops the server and removes the panel from its superview
 * without animation and without firing the dismiss callback.
 * Call this from the owning VC's viewWillDisappear / dealloc.
 */
- (void)stopAndRemove;

/**
 * Optional callback fired (on the main thread) after the dismiss animation
 * completes.  The target is held weakly — the caller must outlive the panel
 * or call stopAndRemove first.
 */
- (void)setDismissTarget:(id)target selector:(SEL)sel;

@end
