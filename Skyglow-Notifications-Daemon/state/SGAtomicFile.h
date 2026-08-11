#ifndef SKYGLOW_SG_ATOMIC_FILE_H
#define SKYGLOW_SG_ATOMIC_FILE_H

#import <Foundation/Foundation.h>
#include <sys/types.h>

BOOL SGAtomicWriteData(NSData *data,
                       NSString *path,
                       mode_t mode,
                       NSError **outError);

BOOL SGAtomicWritePropertyList(id propertyList,
                               NSString *path,
                               mode_t mode,
                               NSError **outError);

BOOL SGDurableRemoveItem(NSString *path, NSError **outError);

#endif
