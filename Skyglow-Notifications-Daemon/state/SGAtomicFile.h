#ifndef SKYGLOW_SG_ATOMIC_FILE_H
#define SKYGLOW_SG_ATOMIC_FILE_H

#import <Foundation/Foundation.h>
#include <sys/types.h>

#define SG_STORAGE_SMALL_FILE_MAX_BYTES 65536

extern NSString * const SGStorageErrorDomain;

/** Builds an NSError in SGStorageErrorDomain carrying the posix detail. */
void SGStorageSetError(NSError **outError, NSInteger code, int posixError);

NSString *SGStorageUUIDString(void);

/** Bounded whole file read */
NSData *SGAtomicReadData(NSString *path, NSUInteger maxLength);

BOOL SGAtomicWriteData(NSData *data,
                       NSString *path,
                       mode_t mode,
                       NSError **outError);

BOOL SGAtomicWritePropertyList(id propertyList,
                               NSString *path,
                               mode_t mode,
                               NSError **outError);

BOOL SGDurableRemoveItem(NSString *path, NSError **outError);

/** rename() plus parent directory fsync so the move survives a crash. */
BOOL SGDurableRenameItem(NSString *fromPath, NSString *toPath, NSError **outError);

/** chown to the mobile user where one exists, no-op on macOS. */
void SGStorageApplyMobileOwnership(NSString *path);

/** chmod 0700 + mobile ownership on an existing directory. */
void SGStorageApplyPrivateDirectoryProtection(NSString *path);

#endif
