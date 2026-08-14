#ifndef SKYGLOW_SG_DURABLE_INBOX_H
#define SKYGLOW_SG_DURABLE_INBOX_H

#import <Foundation/Foundation.h>

extern NSString * const SGDurableEventFormatVersionKey;
extern NSString * const SGDurableEventTypeKey;
extern NSString * const SGDurableEventBundleIdentifierKey;
extern NSString * const SGDurableEventFilePathKey;
extern NSString * const SGDurableEventDeleteApp;

NSString *SGDurableEventEnqueueDeleteApp(NSString *inboxPath,
                                         NSString *bundleIdentifier,
                                         NSError **outError);

NSArray *SGDurableEventPendingEvents(NSString *inboxPath);

BOOL SGDurableEventRemove(NSDictionary *event);

BOOL SGDurableEventQuarantine(NSDictionary *event);

NSUInteger SGDurableEventPurgeForBundleIdentifier(NSString *inboxPath,
                                                  NSString *bundleIdentifier);

#endif
