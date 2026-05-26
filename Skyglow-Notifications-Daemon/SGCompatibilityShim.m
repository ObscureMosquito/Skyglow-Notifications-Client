#import "SGCompatibilityShim.h"
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

/* iOS 4's libSystem.B.dylib doesn't export _environ, SDK 7 code
 * that references it (directly or via posix_spawn / inlined getenv)
 * fails to dlopen on iOS 4 with "Symbol not found: _environ".
 *
 * Marked weak so the linker drops this definition silently when a
 * strong _environ is already in scope — which is the case for our
 * daemon (executable), since crt1.3.1.o ships its own _environ as
 * part of the C runtime startup.  Bundles and dylibs don't link
 * crt1, so for them our weak definition is what dyld resolves
 * against. */
char **environ __attribute__((weak)) = NULL;

/* Subscripting IMPs.  Method signatures match the runtime-emitted
 * selectors exactly so calls like dict[@"k"] / arr[i] / dict[k]=v
 * route here on iOS 4-5 (where the selectors otherwise don't exist). */

static id sgn_dict_subscript_get(id self, SEL _cmd, id key) {
    return [self objectForKey:key];
}

static void sgn_dict_subscript_set(id self, SEL _cmd, id obj, id<NSCopying> key) {
    [self setObject:obj forKey:key];
}

static id sgn_arr_idx_get(id self, SEL _cmd, NSUInteger idx) {
    return [self objectAtIndex:idx];
}

static void sgn_arr_idx_set(id self, SEL _cmd, id obj, NSUInteger idx) {
    [(NSMutableArray *)self replaceObjectAtIndex:idx withObject:obj];
}

/* Auto-install on image load — runs before any Obj-C method in the image
 * can fire, so subscripting in static initializers and early code paths
 * is safe.  Explicit SGNInstallCompatibilityShim() calls remain valid
 * (idempotent) for callers that prefer not to depend on constructor
 * ordering. */
__attribute__((constructor))
static void sgn_compatibility_shim_autoinstall(void) {
    SGNInstallCompatibilityShim();
}

void SGNInstallCompatibilityShim(void) {
    static int installed = 0;
    if (installed) return;
    installed = 1;

    /* Read-side selectors land on the immutable base classes; the mutable
     * subclasses inherit via normal lookup.  Add only when missing so we
     * don't shadow Apple's own implementations on iOS 6+. */

    Class dictCls = [NSDictionary class];
    if (![dictCls instancesRespondToSelector:@selector(objectForKeyedSubscript:)]) {
        class_addMethod(dictCls,
                        @selector(objectForKeyedSubscript:),
                        (IMP)sgn_dict_subscript_get,
                        "@@:@");
    }

    Class arrCls = [NSArray class];
    if (![arrCls instancesRespondToSelector:@selector(objectAtIndexedSubscript:)]) {
        class_addMethod(arrCls,
                        @selector(objectAtIndexedSubscript:),
                        (IMP)sgn_arr_idx_get,
                        "@@:L");
    }

    /* Write-side selectors land on the mutable subclasses — immutable
     * subscript-set would be nonsense.  The runtime emits these only when
     * the compiler sees a mutable target, so missing on immutable is the
     * correct shape. */

    Class mDictCls = [NSMutableDictionary class];
    if (![mDictCls instancesRespondToSelector:@selector(setObject:forKeyedSubscript:)]) {
        class_addMethod(mDictCls,
                        @selector(setObject:forKeyedSubscript:),
                        (IMP)sgn_dict_subscript_set,
                        "v@:@@");
    }

    Class mArrCls = [NSMutableArray class];
    if (![mArrCls instancesRespondToSelector:@selector(setObject:atIndexedSubscript:)]) {
        class_addMethod(mArrCls,
                        @selector(setObject:atIndexedSubscript:),
                        (IMP)sgn_arr_idx_set,
                        "v@:@L");
    }
}
