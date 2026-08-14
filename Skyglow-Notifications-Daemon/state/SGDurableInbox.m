#import "SGDurableInbox.h"
#import "SGAtomicFile.h"
#include <CoreFoundation/CoreFoundation.h>
#include <errno.h>
#include <unistd.h>

NSString * const SGDurableEventFormatVersionKey = @"formatVersion";
static NSString * const SGDurableEventIdentifierKey = @"eventID";
NSString * const SGDurableEventTypeKey = @"type";
NSString * const SGDurableEventBundleIdentifierKey = @"bundleID";
static NSString * const SGDurableEventCreatedAtKey = @"createdAt";
NSString * const SGDurableEventFilePathKey = @"_eventFilePath";
NSString * const SGDurableEventDeleteApp = @"delete_app";

static const NSUInteger SGDurableEventMaximumBytes = 16384;
static const NSUInteger SGDurableEventMaximumBatch = 256;

static NSDictionary *SGDurableEventParseFile(NSString *path) {
    NSData *data = SGAtomicReadData(path, SGDurableEventMaximumBytes);
    if (!data) return nil;
    id parsed = [NSPropertyListSerialization
        propertyListWithData:data
                     options:NSPropertyListMutableContainersAndLeaves
                      format:NULL
                       error:NULL];
    if (![parsed isKindOfClass:[NSDictionary class]]) return nil;
    return parsed;
}

static NSArray *SGDurableEventFilenames(NSString *inboxPath) {
    NSArray *names = [[NSFileManager defaultManager]
        contentsOfDirectoryAtPath:inboxPath error:NULL];
    if (![names count]) return [NSArray array];

    names = [names sortedArrayUsingSelector:@selector(compare:)];
    NSMutableArray *eventNames = [NSMutableArray array];
    for (NSString *name in names) {
        if (![name hasSuffix:@".plist"] || [name hasPrefix:@"."]) continue;
        [eventNames addObject:name];
    }
    return eventNames;
}

static NSString *SGDurableEventEnqueueWithType(NSString *inboxPath,
                                               NSString *type,
                                               NSString *bundleIdentifier,
                                               NSError **outError) {
    if ([inboxPath length] == 0 || [type length] == 0 ||
        [bundleIdentifier length] == 0) {
        SGStorageSetError(outError, 100, EINVAL);
        return nil;
    }

    NSString *eventID = SGStorageUUIDString();
    if (!eventID) {
        SGStorageSetError(outError, 101, ENOMEM);
        return nil;
    }

    NSTimeInterval unixTime =
        CFAbsoluteTimeGetCurrent() + kCFAbsoluteTimeIntervalSince1970;
    unsigned long long microseconds =
        (unsigned long long)(unixTime * 1000000.0);
    NSString *filename = [NSString stringWithFormat:@"%020llu-%@.plist",
                                                    microseconds, eventID];
    NSString *eventPath = [inboxPath stringByAppendingPathComponent:filename];

    NSMutableDictionary *event = [NSMutableDictionary dictionary];
    [event setObject:[NSNumber numberWithInteger:1]
              forKey:SGDurableEventFormatVersionKey];
    [event setObject:eventID forKey:SGDurableEventIdentifierKey];
    [event setObject:type forKey:SGDurableEventTypeKey];
    [event setObject:bundleIdentifier
              forKey:SGDurableEventBundleIdentifierKey];
    [event setObject:[NSNumber numberWithDouble:unixTime]
              forKey:SGDurableEventCreatedAtKey];

    if (!SGAtomicWritePropertyList(event, eventPath, 0600, outError)) return nil;
    return eventPath;
}

NSString *SGDurableEventEnqueueDeleteApp(NSString *inboxPath,
                                         NSString *bundleIdentifier,
                                         NSError **outError) {
    return SGDurableEventEnqueueWithType(inboxPath, SGDurableEventDeleteApp,
                                         bundleIdentifier, outError);
}

NSArray *SGDurableEventPendingEvents(NSString *inboxPath) {
    NSMutableArray *events = [NSMutableArray array];
    for (NSString *name in SGDurableEventFilenames(inboxPath)) {
        if ([events count] >= SGDurableEventMaximumBatch) break;

        NSString *path = [inboxPath stringByAppendingPathComponent:name];
        NSDictionary *parsed = SGDurableEventParseFile(path);

        NSMutableDictionary *envelope = parsed
            ? [NSMutableDictionary dictionaryWithDictionary:parsed]
            : [NSMutableDictionary dictionary];
        [envelope setObject:path forKey:SGDurableEventFilePathKey];
        [events addObject:envelope];
    }
    return events;
}

BOOL SGDurableEventRemove(NSDictionary *event) {
    NSString *path = [event objectForKey:SGDurableEventFilePathKey];
    if ([path length] == 0) return NO;
    return SGDurableRemoveItem(path, NULL);
}

BOOL SGDurableEventQuarantine(NSDictionary *event) {
    NSString *path = [event objectForKey:SGDurableEventFilePathKey];
    if ([path length] == 0) return NO;
    return SGDurableRenameItem(path, [path stringByAppendingString:@".invalid"], NULL);
}

NSUInteger SGDurableEventPurgeForBundleIdentifier(NSString *inboxPath,
                                                  NSString *bundleIdentifier) {
    if ([inboxPath length] == 0 || [bundleIdentifier length] == 0) return 0;

    NSUInteger removed = 0;
    /* Deliberately unbatched: a purge that misses events defeats its point. */
    for (NSString *name in SGDurableEventFilenames(inboxPath)) {
        NSString *path = [inboxPath stringByAppendingPathComponent:name];
        NSDictionary *parsed = SGDurableEventParseFile(path);
        NSString *eventBundle =
            [parsed objectForKey:SGDurableEventBundleIdentifierKey];
        if (![eventBundle isKindOfClass:[NSString class]] ||
            ![eventBundle isEqualToString:bundleIdentifier]) {
            continue;
        }

        if (SGDurableRemoveItem(path, NULL)) {
            removed++;
        }
    }
    return removed;
}
