#ifndef SKYGLOW_SG_STORAGE_H
#define SKYGLOW_SG_STORAGE_H

#import <Foundation/Foundation.h>
#include <sys/types.h>

extern NSString * const SGDurableEventFormatVersionKey;
extern NSString * const SGDurableEventIdentifierKey;
extern NSString * const SGDurableEventTypeKey;
extern NSString * const SGDurableEventBundleIdentifierKey;
extern NSString * const SGDurableEventEnabledKey;
extern NSString * const SGDurableEventCreatedAtKey;
extern NSString * const SGDurableEventFilePathKey;

extern NSString * const SGDurableEventSetAppEnabled;
extern NSString * const SGDurableEventClearAppIntent;
extern NSString * const SGDurableEventDeleteApp;

/**
 * Writes a property list with create-time permissions, fsync, and atomic
 * rename. Readers observe either the old complete file or the new complete
 * file; chmod is not repeated after publication.
 */
BOOL SGAtomicWritePropertyList(id propertyList,
                               NSString *path,
                               mode_t mode,
                               NSError **outError);

/**
 * Persists one immutable event file before its IPC attempt. The returned path
 * identifies the event and may be removed after the daemon acknowledges the
 * corresponding command. Events are generic storage-domain intents and do not
 * contain SpringBoard objects or platform-specific implementation details.
 */
NSString *SGDurableEventEnqueue(NSString *inboxPath,
                                NSString *type,
                                NSString *bundleIdentifier,
                                NSNumber *enabledOrNil,
                                NSError **outError);

/** Returns valid or malformed .plist event envelopes in filename order. */
NSArray *SGDurableEventPendingEvents(NSString *inboxPath);

/** Removes a successfully applied event. Missing files count as success. */
BOOL SGDurableEventRemove(NSDictionary *event);

/** Moves an invalid event out of the active .plist namespace for inspection. */
BOOL SGDurableEventQuarantine(NSDictionary *event);

#endif
