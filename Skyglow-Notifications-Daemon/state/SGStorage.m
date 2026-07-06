#import "SGStorage.h"
#include <CoreFoundation/CoreFoundation.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

NSString * const SGDurableEventFormatVersionKey    = @"formatVersion";
NSString * const SGDurableEventIdentifierKey       = @"eventID";
NSString * const SGDurableEventTypeKey             = @"type";
NSString * const SGDurableEventBundleIdentifierKey = @"bundleID";
NSString * const SGDurableEventEnabledKey          = @"enabled";
NSString * const SGDurableEventCreatedAtKey        = @"createdAt";
NSString * const SGDurableEventFilePathKey          = @"_eventFilePath";

NSString * const SGDurableEventSetAppEnabled = @"set_app_enabled";
NSString * const SGDurableEventDeleteApp = @"delete_app";

static NSString * const SGStorageErrorDomain = @"com.skyglow.storage";
static const NSUInteger SGDurableEventMaximumBytes = 16384;
static const NSUInteger SGDurableEventMaximumBatch = 256;

static void SGStorageSetError(NSError **outError, NSInteger code, int posixError) {
    if (!outError) return;
    NSMutableDictionary *info = [NSMutableDictionary dictionary];
    if (posixError != 0) {
        [info setObject:[NSString stringWithUTF8String:strerror(posixError)]
                 forKey:NSLocalizedDescriptionKey];
        [info setObject:[NSNumber numberWithInt:posixError]
                 forKey:@"errno"];
    }
    *outError = [NSError errorWithDomain:SGStorageErrorDomain
                                   code:code
                               userInfo:info];
}

static NSString *SGStorageUUIDString(void) {
    CFUUIDRef uuid = CFUUIDCreate(kCFAllocatorDefault);
    if (!uuid) return nil;
    CFStringRef string = CFUUIDCreateString(kCFAllocatorDefault, uuid);
    CFRelease(uuid);
    return [(NSString *)string autorelease];
}

static BOOL SGStorageWriteAll(int fd, const uint8_t *bytes, NSUInteger length) {
    NSUInteger offset = 0;
    while (offset < length) {
        ssize_t written = write(fd, bytes + offset, length - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return NO;
        offset += (NSUInteger)written;
    }
    return YES;
}

BOOL SGAtomicWritePropertyList(id propertyList,
                               NSString *path,
                               mode_t mode,
                               NSError **outError) {
    if (outError) *outError = nil;
    if (!propertyList || [path length] == 0) {
        SGStorageSetError(outError, 1, EINVAL);
        return NO;
    }

    NSError *serializationError = nil;
    NSData *data = [NSPropertyListSerialization
        dataWithPropertyList:propertyList
                      format:NSPropertyListBinaryFormat_v1_0
                     options:0
                       error:&serializationError];
    if (!data) {
        if (outError) *outError = serializationError;
        return NO;
    }

    NSString *directory = [path stringByDeletingLastPathComponent];
    NSDictionary *attributes = [NSDictionary dictionaryWithObject:
        [NSNumber numberWithUnsignedLong:0700]
        forKey:NSFilePosixPermissions];
    if (![[NSFileManager defaultManager]
            createDirectoryAtPath:directory
      withIntermediateDirectories:YES
                       attributes:attributes
                            error:outError]) {
        return NO;
    }

    NSString *uuid = SGStorageUUIDString();
    if (!uuid) {
        SGStorageSetError(outError, 2, ENOMEM);
        return NO;
    }
    NSString *temporaryPath = [directory stringByAppendingPathComponent:
        [NSString stringWithFormat:@".%@.tmp", uuid]];

    int fd = open([temporaryPath fileSystemRepresentation],
                  O_WRONLY | O_CREAT | O_EXCL, mode);
    if (fd < 0) {
        SGStorageSetError(outError, 3, errno);
        return NO;
    }

    BOOL ok = (fchmod(fd, mode) == 0) &&
              SGStorageWriteAll(fd, (const uint8_t *)[data bytes], [data length]) &&
              (fsync(fd) == 0);
    int savedError = ok ? 0 : errno;
    if (close(fd) != 0 && ok) {
        ok = NO;
        savedError = errno;
    }

    if (ok && rename([temporaryPath fileSystemRepresentation],
                     [path fileSystemRepresentation]) != 0) {
        ok = NO;
        savedError = errno;
    }

    if (!ok) {
        unlink([temporaryPath fileSystemRepresentation]);
        SGStorageSetError(outError, 4, savedError);
        return NO;
    }

    int directoryFD = open([directory fileSystemRepresentation], O_RDONLY);
    if (directoryFD >= 0) {
        (void)fsync(directoryFD);
        close(directoryFD);
    }
    return YES;
}

NSString *SGDurableEventEnqueue(NSString *inboxPath,
                                NSString *type,
                                NSString *bundleIdentifier,
                                NSNumber *enabledOrNil,
                                NSError **outError) {
    if ([inboxPath length] == 0 || [type length] == 0 ||
        [bundleIdentifier length] == 0) {
        SGStorageSetError(outError, 5, EINVAL);
        return nil;
    }

    NSString *eventID = SGStorageUUIDString();
    if (!eventID) {
        SGStorageSetError(outError, 6, ENOMEM);
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
    if (enabledOrNil) {
        [event setObject:enabledOrNil forKey:SGDurableEventEnabledKey];
    }

    if (!SGAtomicWritePropertyList(event, eventPath, 0600, outError)) return nil;
    return eventPath;
}

NSArray *SGDurableEventPendingEvents(NSString *inboxPath) {
    NSArray *names = [[NSFileManager defaultManager]
        contentsOfDirectoryAtPath:inboxPath error:NULL];
    if (![names count]) return [NSArray array];

    names = [names sortedArrayUsingSelector:@selector(compare:)];
    NSMutableArray *events = [NSMutableArray array];
    for (NSString *name in names) {
        if ([events count] >= SGDurableEventMaximumBatch) break;
        if (![name hasSuffix:@".plist"] || [name hasPrefix:@"."]) continue;

        NSString *path = [inboxPath stringByAppendingPathComponent:name];
        NSDictionary *attributes = [[NSFileManager defaultManager]
            attributesOfItemAtPath:path error:NULL];
        unsigned long long size = [attributes fileSize];

        NSMutableDictionary *envelope = nil;
        if (size > 0 && size <= SGDurableEventMaximumBytes) {
            NSData *data = [NSData dataWithContentsOfFile:path];
            id parsed = data ? [NSPropertyListSerialization
                propertyListWithData:data
                             options:NSPropertyListMutableContainersAndLeaves
                              format:NULL
                               error:NULL] : nil;
            if ([parsed isKindOfClass:[NSDictionary class]]) {
                envelope = [NSMutableDictionary dictionaryWithDictionary:parsed];
            }
        }
        if (!envelope) envelope = [NSMutableDictionary dictionary];
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
