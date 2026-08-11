#import "SGCompatibilityShim.h"
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

/** iOS 4 lacks _environ; SDK 7 code that references it fails to dlopen. */
char **environ __attribute__((weak)) = NULL;

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

__attribute__((constructor))
static void sgn_compatibility_shim_autoinstall(void) {
    SGNInstallCompatibilityShim();
}

void SGNInstallCompatibilityShim(void) {
    static int installed = 0;
    if (installed) return;
    installed = 1;

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
