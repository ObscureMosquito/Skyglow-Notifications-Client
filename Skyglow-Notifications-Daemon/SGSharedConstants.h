#ifndef SKYGLOW_SG_SHARED_CONSTANTS_H
#define SKYGLOW_SG_SHARED_CONSTANTS_H

#import <CoreFoundation/CoreFoundation.h>

/**
 * Constants shared across all three SGN modules (daemon, SB tweak, prefs
 * bundle).  Anything that has to match across module boundaries file
 * paths, iOS version branches, IPC timeouts lives here so a change is
 * one edit instead of N.
 *
 * All path strings are relative to the system root.  Callers must wrap
 * them in SGPath() (the rootless-aware path helper) before use; SGPath
 * is defined inline in SGConfiguration.h (daemon) and SNDataManager.m
 * (prefs), both implementations are identical, they prepend /var/jb
 * when the rootless marker exists.
 */

#pragma mark - File Paths (system-root relative; wrap with SGPath)

/* User-intent SSOT: per-bundle Skyglow choice + pendingDeletions.
 * Written by: prefs bundle (toggle, swipe-delete), SB tweak (uninstall +
 *   prompt acceptance), daemon (clearing pendingDeletions only).
 * Read by: everyone. */
#define SG_PREFS_PLIST_PATH         @"/var/mobile/Library/Preferences/com.skyglow.sndp.plist"

/* Per-profile server config (server address, certificate path, device
 * address, private key path).  Indexed 1-5; format string takes an
 * NSInteger as %ld. */
#define SG_PROFILE_PLIST_FORMAT     @"/var/mobile/Library/Preferences/com.skyglow.sndp-profile%ld.plist"

/* Operational SSOT: tokens, e2ee keys, routing keys, mute flags, retry
 * queue.  Owned exclusively by the daemon. */
#define SG_DB_PATH                  @"/var/mobile/Library/SkyglowNotifications/sqlite.db"

/* Daemon lifecycle. */
#define SG_LOG_PATH                 @"/var/log/skyglow.log"
#define SG_PID_PATH                 @"/var/run/skyglow_daemon.pid"

#pragma mark - iOS Version Branches

/**
 * CFCoreFoundationVersionNumber thresholds for the major iOS releases we
 * branch on.  Apple ships some of these as kCFCoreFoundationVersionNumber_iOS_*
 * in <CoreFoundation/CFBase.h>, but coverage is patchy and naming has
 * shifted over the years so we define our own so the meaning of each
 * version check is unambiguous at the call site.
 *
 */
#define SGN_CF_VERSION_IOS_7_0   847.20   /* push delivery path: SBRemoteNotificationServer connection:didReceiveMessageForTopic: vs didReceiveIncomingMessage: */
#define SGN_CF_VERSION_IOS_8_0   1140.0   /* uninstall hook: SBApplicationUninstallationOperation (≤7) vs SBApplicationController.uninstallApplication: (≥8) */
#define SGN_CF_VERSION_IOS_9_0   1200.0   /* registration: classic SBRemoteNotificationServer (≤8) vs UNNotificationRegistrarConnectionListener (≥9) */

/* Convenience predicates read clearer than raw inequalities at the
 * call site.  Use SGN_IS_PRE_IOS_X when the "classic" code path is what
 * runs below the threshold (matches our hooks' code shape). */
#define SGN_IS_PRE_IOS_7   (kCFCoreFoundationVersionNumber <  SGN_CF_VERSION_IOS_7_0)
#define SGN_IS_PRE_IOS_8   (kCFCoreFoundationVersionNumber <  SGN_CF_VERSION_IOS_8_0)
#define SGN_IS_PRE_IOS_9   (kCFCoreFoundationVersionNumber <  SGN_CF_VERSION_IOS_9_0)

#endif
