#import <UIKit/UIKit.h>

/**
 * SNLogTailViewController — live tail of /var/log/skyglow.log.
 *
 * Reads the trailing window of the daemon's log file on a 1Hz timer,
 * applies a level filter, trims long daemon prefixes, and auto-follows
 * unless the user has scrolled away from the bottom. Designed to be
 * pushed from SNDebugViewController.
 *
 * Built as a grouped UITableViewController so it inherits the Settings
 * background, section header styling, and inset margins for free —
 * matching SNDebugViewController and SNServerInfoViewController.
 *
 * Read-only — no edits, no daemon control.  Bug reports use the Copy
 * button in the navigation bar to dump the raw (untrimmed) log to the
 * pasteboard.
 */
@interface SNLogTailViewController : UITableViewController
@end
