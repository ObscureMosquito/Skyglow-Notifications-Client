#ifndef SKYGLOW_SG_PLATFORM_CONSTANTS_H
#define SKYGLOW_SG_PLATFORM_CONSTANTS_H

#import <Foundation/Foundation.h>

/** owner of daemon state files so SpringBoard and the preference bundle read them. */
#define SG_STATE_FILE_OWNER "mobile"

/** resolves a system root relative constant to its real path  */
static inline NSString *SGPath(NSString *path) {
    static int isRootless = -1;
    if (__builtin_expect(isRootless < 0, 0)) {
        isRootless = [[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"] ? 1 : 0;
    }
    return isRootless ? [@"/var/jb" stringByAppendingString:path] : path;
}

#endif
