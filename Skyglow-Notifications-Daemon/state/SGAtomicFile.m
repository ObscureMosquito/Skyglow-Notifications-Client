#import "SGAtomicFile.h"
#include <CoreFoundation/CoreFoundation.h>
#include <TargetConditionals.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

NSString * const SGStorageErrorDomain = @"com.skyglow.storage";

void SGStorageSetError(NSError **outError, NSInteger code, int posixError) {
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

NSString *SGStorageUUIDString(void) {
    CFUUIDRef uuid = CFUUIDCreate(kCFAllocatorDefault);
    if (!uuid) return nil;
    CFStringRef string = CFUUIDCreateString(kCFAllocatorDefault, uuid);
    CFRelease(uuid);
    return [(NSString *)string autorelease];
}

void SGStorageApplyMobileOwnership(NSString *path) {
#if !TARGET_OS_OSX
    struct passwd *mobile = getpwnam("mobile");
    if (mobile) {
        (void)chown([path fileSystemRepresentation],
                    mobile->pw_uid, mobile->pw_gid);
    }
#else
    (void)path;
#endif
}

void SGStorageApplyPrivateDirectoryProtection(NSString *path) {
    struct stat st;
    if (stat([path fileSystemRepresentation], &st) != 0 ||
        !S_ISDIR(st.st_mode)) {
        return;
    }
    chmod([path fileSystemRepresentation], 0700);
    SGStorageApplyMobileOwnership(path);
}

static void SGStorageFsyncParentDirectory(NSString *path) {
    NSString *directory = [path stringByDeletingLastPathComponent];
    int directoryFD = open([directory fileSystemRepresentation], O_RDONLY);
    if (directoryFD >= 0) {
        (void)fsync(directoryFD);
        close(directoryFD);
    }
}

NSData *SGAtomicReadData(NSString *path, NSUInteger maxLength) {
    if ([path length] == 0) return nil;

    struct stat st;
    if (stat([path fileSystemRepresentation], &st) != 0 ||
        !S_ISREG(st.st_mode)) {
        return nil;
    }
    if (st.st_size <= 0 || (unsigned long long)st.st_size > maxLength) {
        return nil;
    }
    return [NSData dataWithContentsOfFile:path];
}

static BOOL SGAtomicFileWriteAll(int fd, const uint8_t *bytes, NSUInteger length) {
    NSUInteger offset = 0;
    while (offset < length) {
        ssize_t written = write(fd, bytes + offset, length - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return NO;
        offset += (NSUInteger)written;
    }
    return YES;
}

BOOL SGAtomicWriteData(NSData *data,
                       NSString *path,
                       mode_t mode,
                       NSError **outError) {
    if (outError) *outError = nil;
    if (!data || [path length] == 0) {
        SGStorageSetError(outError, 1, EINVAL);
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
              SGAtomicFileWriteAll(fd, (const uint8_t *)[data bytes], [data length]) &&
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

    SGStorageFsyncParentDirectory(path);
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

    return SGAtomicWriteData(data, path, mode, outError);
}

BOOL SGDurableRemoveItem(NSString *path, NSError **outError) {
    if (outError) *outError = nil;
    if ([path length] == 0) {
        SGStorageSetError(outError, 1, EINVAL);
        return NO;
    }

    if (unlink([path fileSystemRepresentation]) != 0 && errno != ENOENT) {
        SGStorageSetError(outError, 5, errno);
        return NO;
    }

    SGStorageFsyncParentDirectory(path);
    return YES;
}

BOOL SGDurableRenameItem(NSString *fromPath, NSString *toPath, NSError **outError) {
    if (outError) *outError = nil;
    if ([fromPath length] == 0 || [toPath length] == 0) {
        SGStorageSetError(outError, 1, EINVAL);
        return NO;
    }

    if (rename([fromPath fileSystemRepresentation],
               [toPath fileSystemRepresentation]) != 0) {
        if (errno == ENOENT) return YES;
        SGStorageSetError(outError, 6, errno);
        return NO;
    }

    SGStorageFsyncParentDirectory(toPath);
    if (![[fromPath stringByDeletingLastPathComponent]
            isEqualToString:[toPath stringByDeletingLastPathComponent]]) {
        SGStorageFsyncParentDirectory(fromPath);
    }
    return YES;
}
