#ifndef SKYGLOW_SG_SHARED_CONSTANTS_H
#define SKYGLOW_SG_SHARED_CONSTANTS_H

#import <CoreFoundation/CoreFoundation.h>

#pragma mark - File Paths (system-root relative; wrap with SGPath)

#define SG_PREFS_PLIST_PATH         @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist"
#define SG_PROFILE_PLIST_FORMAT     @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile%ld.plist"
#define SG_DB_PATH                  @"/var/mobile/Library/SkyglowNotifications/sqlite.db"
#define SG_DURABLE_EVENT_INBOX_PATH @"/var/mobile/Library/SkyglowNotifications/inbox"
#define SG_LOG_PATH                 @"/var/log/sgn.log"
#define SG_PID_PATH                 @"/var/run/skyglow_daemon.pid"

#endif
