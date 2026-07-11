#ifndef SKYGLOW_SG_ATOMIC_FILE_H
#define SKYGLOW_SG_ATOMIC_FILE_H

#import <Foundation/Foundation.h>
#include <sys/types.h>

/**
 * Writes raw bytes with create-time permissions, fsync, and atomic rename.
 * Readers observe either the old complete file or the new complete file;
 * chmod is not repeated after publication.
 */
BOOL SGAtomicWriteData(NSData *data,
                       NSString *path,
                       mode_t mode,
                       NSError **outError);

/**
 * Serializes a property list to binary format and publishes it through
 * SGAtomicWriteData.
 */
BOOL SGAtomicWritePropertyList(id propertyList,
                               NSString *path,
                               mode_t mode,
                               NSError **outError);

/** Removes a file and fsyncs its containing directory. Missing is success. */
BOOL SGDurableRemoveItem(NSString *path, NSError **outError);

#endif
