#ifndef SKYGLOW_SG_DURABLE_INBOX_H
#define SKYGLOW_SG_DURABLE_INBOX_H

#import <Foundation/Foundation.h>

/**
 * Durable missed-uninstall inbox: one immutable plist file per event,
 * published atomically.
 */

extern NSString * const SGDurableEventFormatVersionKey;
extern NSString * const SGDurableEventIdentifierKey;
extern NSString * const SGDurableEventTypeKey;
extern NSString * const SGDurableEventBundleIdentifierKey;
extern NSString * const SGDurableEventCreatedAtKey;
extern NSString * const SGDurableEventFilePathKey;
extern NSString * const SGDurableEventDeleteApp;

/**
 * Persists one immutable missed-uninstall event before its IPC attempt. The
 * returned path identifies the event and may be removed after the daemon
 * acknowledges SGCMSG_DELETE_APP. The payload intentionally contains only a
 * platform-neutral bundle identifier.
 */
NSString *SGDurableEventEnqueueDeleteApp(NSString *inboxPath,
                                         NSString *bundleIdentifier,
                                         NSError **outError);

/** Returns valid or malformed .plist event envelopes in filename order. */
NSArray *SGDurableEventPendingEvents(NSString *inboxPath);

/** Removes a successfully applied event. Missing files count as success. */
BOOL SGDurableEventRemove(NSDictionary *event);

/** Moves an invalid event out of the active .plist namespace for inspection. */
BOOL SGDurableEventQuarantine(NSDictionary *event);

/**
 * Removes every parseable pending event for one bundle identifier,
 * regardless of type or age.
 */
NSUInteger SGDurableEventPurgeForBundleIdentifier(NSString *inboxPath,
                                                  NSString *bundleIdentifier);

#endif
