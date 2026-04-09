#import <UIKit/UIKit.h>
#import <Preferences/PSSpecifier.h>
#import <Preferences/PSTableCell.h>
#import <Preferences/PSListController.h>
#import <Preferences/PSRootController.h>
#import <objc/runtime.h>

extern void MSHookMessageEx(Class _class, SEL message, IMP hook, IMP *old);

static NSString *const kSkyglowID       = @"SkyglowNotificationsID";
static NSString *const kSGNBundleObjKey = @"sgn_bundle_obj";
static NSString *const kSGNPlistNameKey = @"sgn_plist_name";

@interface SGNCustomListController : PSListController
@end

@implementation SGNCustomListController

- (NSBundle *)bundle {
    NSBundle *b = [self.specifier propertyForKey:kSGNBundleObjKey];
    return b ?: [super bundle];
}

- (id)specifiers {
    if (!_specifiers) {
        NSString *plist = [self.specifier propertyForKey:kSGNPlistNameKey];
        if (!plist.length) plist = @"Root";
        _specifiers = [self loadSpecifiersFromPlistName:plist target:self];
    }
    return _specifiers;
}

- (id)navigationTitle {
    return self.specifier.name;
}

@end

static NSBundle *_sgLoadBundle(void) {
    static NSBundle *bundle = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString *path = @"/Library/PreferenceBundles/SGNPreferenceBundle.bundle";
        bundle = [NSBundle bundleWithPath:path];
        [bundle load];
    });
    return bundle;
}

static PSSpecifier *_sgBuildSkyglowSpecifier(void) {
    NSBundle *prefBundle = _sgLoadBundle();
    if (!prefBundle) return nil;

    Class rootCls = [prefBundle principalClass];
    if (!rootCls) rootCls = [prefBundle classNamed:@"SNRootListController"];
    if (!rootCls) return nil;

    PSSpecifier *spec =
        [PSSpecifier preferenceSpecifierNamed:@"Skyglow Notifications"
                                      target:nil
                                         set:NULL
                                         get:NULL
                                      detail:rootCls
                                        cell:PSLinkCell
                                        edit:nil];

    [spec setIdentifier:kSkyglowID];
    if (prefBundle) [spec setProperty:prefBundle forKey:kSGNBundleObjKey];
    [spec setProperty:@"Root" forKey:kSGNPlistNameKey];

    UIImage *icon = [UIImage imageWithContentsOfFile:
        [@"/Library/PreferenceBundles/SGNPreferenceBundle.bundle"
            stringByAppendingPathComponent:@"icon.png"]];
    if (icon) [spec setProperty:icon forKey:@"iconImage"];

    return spec;
}

static IMP  _sgOrigNotifSpecifiers = NULL;
static BOOL _sgNotifHookInstalled  = NO;

static NSMutableArray * _sgNotifSpecifiersHook(id self, SEL _cmd) {
    NSMutableArray *specifiers =
        ((NSMutableArray *(*)(id, SEL))_sgOrigNotifSpecifiers)(self, _cmd);
    if (!specifiers) return specifiers;

    @try {
        for (PSSpecifier *s in specifiers) {
            if ([[s identifier] isEqualToString:kSkyglowID]) return specifiers;
        }

        PSSpecifier *skyglowSpec = _sgBuildSkyglowSpecifier();
        if (!skyglowSpec) return specifiers;

        /*
         * Place Skyglow right after the Do Not Disturb link so it
         * sits in the same visual group.  Walk the specifiers looking
         * for a known DND identifier; fall back to the end of the
         * first group section if not found.
         */
        NSUInteger insertIdx = NSNotFound;
        for (NSUInteger i = 0; i < specifiers.count; i++) {
            NSString *ident = [(PSSpecifier *)specifiers[i] identifier];
            if ([ident isEqualToString:@"DO_NOT_DISTURB"] ||
                [ident isEqualToString:@"FOCUS"] ||
                [ident isEqualToString:@"DO_NOT_DISTURB_ID"]) {
                insertIdx = i + 1;
                break;
            }
        }

        if (insertIdx == NSNotFound) {
            if (specifiers.count > 0 &&
                [(PSSpecifier *)specifiers[0] cellType] == 0 /* PSGroupCell */) {
                insertIdx = 1;
            } else {
                insertIdx = 0;
            }
        }

        [specifiers insertObject:skyglowSpec atIndex:insertIdx];
    } @catch (NSException *e) {
        NSLog(@"[Skyglow] Exception in notification controller hook: %@", e);
    }

    return specifiers;
}

static void _sgTryHookNotifController(NSMutableArray *specifiers) {
    if (_sgNotifHookInstalled) return;

    @try {
        NSUInteger notifIdx = NSNotFound;
        for (NSUInteger i = 0; i < specifiers.count; i++) {
            NSString *ident = [(PSSpecifier *)specifiers[i] identifier];
            if ([ident isEqualToString:@"NOTIFICATIONS"] ||
                [ident isEqualToString:@"NOTIFICATIONS_ID"]) {
                notifIdx = i;
                break;
            }
        }
        if (notifIdx == NSNotFound) return;

        Class detailCls = Nil;
        for (NSUInteger j = notifIdx; j < specifiers.count && j < notifIdx + 3; j++) {
            PSSpecifier *spec = (PSSpecifier *)specifiers[j];
            if ([spec respondsToSelector:@selector(detailControllerClass)]) {
                Class cls = [spec detailControllerClass];
                if (cls) { detailCls = cls; break; }
            }
        }
        if (!detailCls) return;

        if (!class_getInstanceMethod(detailCls, @selector(specifiers))) return;

        MSHookMessageEx(detailCls, @selector(specifiers),
                        (IMP)_sgNotifSpecifiersHook, &_sgOrigNotifSpecifiers);

        _sgNotifHookInstalled = YES;
        NSLog(@"[Skyglow] Hooked %@ — Skyglow will appear inside Notifications pane.",
              NSStringFromClass(detailCls));
    } @catch (NSException *e) {
        NSLog(@"[Skyglow] Failed to hook notification controller: %@", e);
    }
}

%hook PrefsListController

- (NSMutableArray *)specifiers {
    NSMutableArray *specifiers = %orig;
    if (!specifiers) return specifiers;

    _sgTryHookNotifController(specifiers);

    if (_sgNotifHookInstalled) return specifiers;

    for (PSSpecifier *spec in specifiers) {
        if ([[spec identifier] isEqualToString:kSkyglowID]) return specifiers;
    }

    NSUInteger insertIndex = 2;
    for (NSUInteger i = 0; i < specifiers.count; i++) {
        NSString *ident = [(PSSpecifier *)specifiers[i] identifier];
        if ([ident isEqualToString:@"NOTIFICATIONS"] ||
            [ident isEqualToString:@"NOTIFICATIONS_ID"]) {
            insertIndex = i + 1;
            break;
        }
    }

    PSSpecifier *skyglowSpec = _sgBuildSkyglowSpecifier();
    if (!skyglowSpec) return specifiers;

    if (insertIndex < specifiers.count)
        [specifiers insertObject:skyglowSpec atIndex:insertIndex];
    else
        [specifiers addObject:skyglowSpec];

    return specifiers;
}

%end
