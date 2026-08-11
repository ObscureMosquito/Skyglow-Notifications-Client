#ifndef SKYGLOW_SG_SHARED_CONSTANTS_H
#define SKYGLOW_SG_SHARED_CONSTANTS_H

#import <CoreFoundation/CoreFoundation.h>

#pragma mark - File Paths (system-root relative; wrap with SGPath)

#define SG_PREFS_PLIST_PATH         @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist"
#define SG_PROFILE_PLIST_FORMAT     @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile%ld.plist"
#define SG_DB_PATH                  @"/var/mobile/Library/SkyglowNotifications/sqlite.db"
/* Mobile-writable directory for one-file-per-missed-uninstall records. */
#define SG_DURABLE_EVENT_INBOX_PATH @"/var/mobile/Library/SkyglowNotifications/inbox"
#define SG_LOG_PATH                 @"/var/log/sgn.log"
#define SG_PID_PATH                 @"/var/run/skyglow_daemon.pid"

#pragma mark - iOS Version Branches

#define SGN_CF_VERSION_IOS_6_0 700.0    /* push delivery path: SBRemoteNotificationServer connection:didReceiveMessageForTopic: vs didReceiveIncomingMessage: */
#define SGN_CF_VERSION_IOS_7_0 847.20   
#define SGN_CF_VERSION_IOS_8_0 1140.0   /* uninstall hook: SBApplicationUninstallationOperation (≤7) vs SBApplicationController.uninstallApplication: (≥8) */
#define SGN_CF_VERSION_IOS_9_0 1200.0   /* registration: classic SBRemoteNotificationServer (≤8) vs UNNotificationRegistrarConnectionListener (≥9) */

#define SGN_IS_PRE_IOS_6 (kCFCoreFoundationVersionNumber <  SGN_CF_VERSION_IOS_6_0)
#define SGN_IS_PRE_IOS_7 (kCFCoreFoundationVersionNumber <  SGN_CF_VERSION_IOS_7_0)
#define SGN_IS_PRE_IOS_8 (kCFCoreFoundationVersionNumber <  SGN_CF_VERSION_IOS_8_0)
#define SGN_IS_PRE_IOS_9 (kCFCoreFoundationVersionNumber <  SGN_CF_VERSION_IOS_9_0)

#endif
