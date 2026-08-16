#ifndef SKYGLOW_SG_SHARED_CONSTANTS_H
#define SKYGLOW_SG_SHARED_CONSTANTS_H

#import <CoreFoundation/CoreFoundation.h>
#include <stdbool.h>
#include <stddef.h>

#pragma mark - File Paths

#define SG_PREFS_PLIST_PATH         @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist"
#define SG_PROFILE_PLIST_FORMAT     @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile%ld.plist"
#define SG_PROFILE_STATE_DIRECTORY  @"/var/mobile/Library/SkyglowNotifications"
#define SG_DB_PATH                  @"/var/mobile/Library/SkyglowNotifications/sqlite.db"
#define SG_DURABLE_EVENT_INBOX_PATH @"/var/mobile/Library/SkyglowNotifications/inbox"
#define SG_LOG_PATH                 @"/var/log/sgn.log"
#define SG_PID_PATH                 @"/var/run/sgn.pid"

#pragma mark - Preference Keys

#define SG_PREFS_KEY_APP_STATUS     @"appStatus"

#pragma mark - Profiles

#define SG_PROFILE_INDEX_MAX 5

#endif
