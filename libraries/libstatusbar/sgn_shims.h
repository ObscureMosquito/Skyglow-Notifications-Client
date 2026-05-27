/* Compatibility shims applied via -include after the SDK headers but
 * before the canonical libstatusbar sources.  Lets us patch around small
 * SDK-vs-source drift without modifying upstream files. */
#ifndef SGN_LSB_SHIMS_H
#define SGN_LSB_SHIMS_H

#include <CoreFoundation/CFNotificationCenter.h>
#include <dlfcn.h>

/* iOS 6+ SDK promoted CFNotificationSuspensionBehavior to a strong enum.
 * libstatusbar passes literal 0/NULL — which is no longer convertible
 * implicitly in C++.  The macro re-routes the calls through a wrapper
 * that does the explicit cast.  Defining it AFTER the SDK header avoids
 * polluting the prototype declaration. */
#ifdef __cplusplus
static inline void SGN_CFNCAddObserver(CFNotificationCenterRef c, const void *o,
        CFNotificationCallback cb, CFStringRef n, const void *obj, int b) {
    CFNotificationCenterAddObserver(c, o, cb, n, obj, (CFNotificationSuspensionBehavior)b);
}
#define CFNotificationCenterAddObserver SGN_CFNCAddObserver
#endif

#endif
