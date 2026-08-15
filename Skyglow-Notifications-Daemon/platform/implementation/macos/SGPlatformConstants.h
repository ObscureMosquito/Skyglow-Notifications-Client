#ifndef SKYGLOW_SG_PLATFORM_CONSTANTS_H
#define SKYGLOW_SG_PLATFORM_CONSTANTS_H

#import <Foundation/Foundation.h>

/** state files keep the daemon's own (root) ownership. */
#define SG_STATE_FILE_OWNER NULL

/** resolves a system root relative constant to its real path. */
static inline NSString *SGPath(NSString *path) {
    return [@"/usr/local/var/skyglow" stringByAppendingString:path];
}

#endif
