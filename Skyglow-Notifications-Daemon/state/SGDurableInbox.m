#import "SGDurableInbox.h"
#import "SGAtomicFile.h"
#include <CoreFoundation/CoreFoundation.h>
#include <errno.h>
#include <unistd.h>

NSString * const SGDurableEventFormatVersionKey = @"formatVersion";
NSString * const SGDurableEventIdentifierKey = @"eventID";
NSString * const SGDurableEventTypeKey = @"type";
NSString * const SGDurableEventBundleIdentifierKey = @"bundleID";
NSString * const SGDurableEventCreatedAtKey = @"createdAt";
NSString * const SGDurableEventFilePathKey = @"_eventFilePath";
NSString * const SGDurableEventDeleteApp = @"delete_app";

static NSString * const SGDurableInboxErrorDomain = @"com.skyglow.storage";
static const NSUInteger SGDurableEventMaximumBytes = 16384;
static const NSUInteger SGDurableEventMaximumBatch = 256;

static void SGDurableInboxSetError(NSError **outError, NSInteger code, int posixError) {
    if (!outError) return;
    NSMutableDictionary *info = [NSMutableDictionary dictionary];
    if (posixError != 0) {
        [info setObject:[NSString stringWithUTF8String:strerror(posixError)]
                 forKey:NSLocalizedDescriptionKey];
        [info setObject:[NSNumber numberWithInt:posixError]
                 forKey:@"errno"];
    }
    *outError = [NSError errorWithDomain:SGDurableInboxErrorDomain
                                   code:code
                               userInfo:info];
}

static NSString *SGDurableInboxUUIDString(void) {
    CFUUIDRef uuid = CFUUIDCreate(kCFAllocatorDefault);
    if (!uuid) return nil;
    CFStringRef string = CFUUIDCreateString(kCFAllocatorDefault, uuid);
    CFRelease(uuid);
    return [(NSString *)string autorelease];
}

/** Parses one published event file into a dictionary, or nil when the file
 *  is missing, oversized, or not a plist dictionary. */
static NSDictionary *SGDurableEventParseFile(NSString *path) {
    NSDictionary *attributes = [[NSFileManager defaultManager]
        attributesOfItemAtPath:path error:NULL];
    unsigned long long size = [attributes fileSize];
    if (size == 0 || size > SGDurableEventMaximumBytes) return nil;

    NSData *data = [NSData dataWithContentsOfFile:path];
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
        SGDurableInboxSetError(outError, 5, EINVAL);
        return nil;
    }

    NSString *eventID = SGDurableInboxUUIDString();
    if (!eventID) {
        SGDurableInboxSetError(outError, 6, ENOMEM);
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
    if (unlink([path fileSystemRepresentation]) == 0 || errno == ENOENT) {
        return YES;
    }
    return NO;
}

BOOL SGDurableEventQuarantine(NSDictionary *event) {
    NSString *path = [event objectForKey:SGDurableEventFilePathKey];
    if ([path length] == 0) return NO;
    NSString *quarantinePath = [path stringByAppendingString:@".invalid"];
    if (rename([path fileSystemRepresentation],
               [quarantinePath fileSystemRepresentation]) == 0 ||
        errno == ENOENT) {
        return YES;
    }
    return NO;
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

        if (unlink([path fileSystemRepresentation]) == 0) {
            removed++;
        }
    }
    return removed;
}
