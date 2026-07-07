#import "SGControlAuthorization.h"

#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>

static const char * const kSGCAllowedSenderPaths[] = {
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
    "/Applications/Preferences.app/Preferences",
    "/System/Applications/Preferences.app/Preferences",
    "/Applications/Settings.app/Settings",
    "/System/Applications/Settings.app/Settings",
};

static const char * const kSGCPhysicalPathPrefixes[] = {
    "/var/jb",
};

static BOOL SGCResolveSenderName(pid_t pid, char *out, size_t capacity) {
    if (!out || capacity == 0) return NO;
    out[0] = '\0';
    if (pid <= 0) return NO;

    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    struct kinfo_proc process;
    size_t length = sizeof(process);
    if (sysctl(mib, 4, &process, &length, NULL, 0) != 0 || length == 0) {
        return NO;
    }
    strlcpy(out, process.kp_proc.p_comm, capacity);
    return out[0] != '\0';
}

static BOOL SGCPathIsSafeAbsolute(const char *path, size_t capacity) {
    if (!path || capacity < 2 || path[0] != '/') return NO;
    size_t length = strnlen(path, capacity);
    if (length == 0 || length >= capacity) return NO;
    for (size_t i = 0; i < length; i++) {
        unsigned char byte = (unsigned char)path[i];
        if (byte < 0x20 || byte > 0x7e) return NO;
    }
    return YES;
}

static BOOL SGCResolveSenderPath(pid_t pid, char *out, size_t capacity) {
    if (!out || capacity == 0 || pid <= 0) return NO;
    out[0] = '\0';

    typedef int (*SGCProcPIDPathFn)(int, void *, uint32_t);
    static SGCProcPIDPathFn procPIDPath = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        procPIDPath = (SGCProcPIDPathFn)dlsym(RTLD_DEFAULT, "proc_pidpath");
    });
    if (procPIDPath && capacity <= UINT32_MAX) {
        int copied = procPIDPath((int)pid, out, (uint32_t)capacity);
        if (copied > 0) {
            out[capacity - 1] = '\0';
            if (SGCPathIsSafeAbsolute(out, capacity)) return YES;
        }
        out[0] = '\0';
    }

    /* Compatibility path for old kernels without proc_pidpath. Some releases
     * return argument metadata here, so accept only a printable absolute path. */
    int mib[3] = { CTL_KERN, KERN_PROCARGS2, pid };
    size_t size = 0;
    if (sysctl(mib, 3, NULL, &size, NULL, 0) != 0 ||
        size <= sizeof(int) || size > 65536) {
        return NO;
    }

    char *arguments = (char *)malloc(size);
    if (!arguments) return NO;
    BOOL resolved = NO;
    if (sysctl(mib, 3, arguments, &size, NULL, 0) == 0 &&
        size > sizeof(int)) {
        const char *candidate = arguments + sizeof(int);
        size_t available = size - sizeof(int);
        size_t length = strnlen(candidate, available);
        if (length > 0 && length < available && length < capacity &&
            SGCPathIsSafeAbsolute(candidate, available)) {
            memcpy(out, candidate, length);
            out[length] = '\0';
            resolved = YES;
        }
    }
    free(arguments);
    return resolved;
}

static const char *SGCPathBasename(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static BOOL SGCPathMatchesAllowedPath(const char *senderPath,
                                      const char *allowedPath) {
    if (strcmp(senderPath, allowedPath) == 0) return YES;
    for (size_t i = 0;
         i < sizeof(kSGCPhysicalPathPrefixes) /
             sizeof(kSGCPhysicalPathPrefixes[0]);
         i++) {
        size_t prefixLength = strlen(kSGCPhysicalPathPrefixes[i]);
        if (strncmp(senderPath, kSGCPhysicalPathPrefixes[i], prefixLength) == 0 &&
            strcmp(senderPath + prefixLength, allowedPath) == 0) {
            return YES;
        }
    }
    return NO;
}

static BOOL SGCSenderMatchesResolvedAllowed(const char *senderPath) {
    enum { kSGCAllowedCount = sizeof(kSGCAllowedSenderPaths) /
                              sizeof(kSGCAllowedSenderPaths[0]) };
    static char resolved[kSGCAllowedCount][PATH_MAX];
    static bool resolvedOK[kSGCAllowedCount];
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        for (size_t i = 0; i < kSGCAllowedCount; i++) {
            resolvedOK[i] =
                (realpath(kSGCAllowedSenderPaths[i], resolved[i]) != NULL);
        }
    });
    for (size_t i = 0; i < kSGCAllowedCount; i++) {
        if (resolvedOK[i] && strcmp(senderPath, resolved[i]) == 0) return YES;
    }
    return NO;
}

bool SGControlSenderIsAuthorized(pid_t pid,
                                 uid_t euid,
                                 char *outName,
                                 size_t nameCapacity,
                                 char *outPath,
                                 size_t pathCapacity) {
    BOOL hasName = SGCResolveSenderName(pid, outName, nameCapacity);
    BOOL hasPath = SGCResolveSenderPath(pid, outPath, pathCapacity);

    if (euid == 0) return true;
    if (euid != 501) return false;

    size_t count =
        sizeof(kSGCAllowedSenderPaths) / sizeof(kSGCAllowedSenderPaths[0]);
    if (hasPath) {
        for (size_t i = 0; i < count; i++) {
            if (SGCPathMatchesAllowedPath(outPath,
                                          kSGCAllowedSenderPaths[i])) {
                return true;
            }
        }
        if (SGCSenderMatchesResolvedAllowed(outPath)) return true;
        return false;
    }

    if (hasName) {
        for (size_t i = 0; i < count; i++) {
            if (strcmp(outName,
                       SGCPathBasename(kSGCAllowedSenderPaths[i])) == 0) {
                return true;
            }
        }
    }
    return false;
}
