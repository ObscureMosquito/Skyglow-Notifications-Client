#ifndef SKYGLOW_SN_INTERFACE_COLORS_H
#define SKYGLOW_SN_INTERFACE_COLORS_H

#import <UIKit/UIKit.h>

static inline UIColor *SNInterfaceColor(NSString *selectorName,
                                        UIColor *fallback) {
    Class colorClass = [UIColor class];
    SEL selector = NSSelectorFromString(selectorName);
    if ([colorClass respondsToSelector:selector]) {
        IMP implementation = [colorClass methodForSelector:selector];
        if (implementation) {
            return ((UIColor *(*)(id, SEL))implementation)(colorClass, selector);
        }
    }
    return fallback;
}

static inline BOOL SNSupportsSemanticColors(void) {
    return [[UIColor class] respondsToSelector:NSSelectorFromString(@"labelColor")];
}

static inline UIColor *SNLabelColor(UIColor *fallback) {
    return SNInterfaceColor(@"labelColor", fallback);
}

static inline UIColor *SNSecondaryLabelColor(UIColor *fallback) {
    return SNInterfaceColor(@"secondaryLabelColor", fallback);
}

static inline UIColor *SNTertiaryLabelColor(UIColor *fallback) {
    return SNInterfaceColor(@"tertiaryLabelColor", fallback);
}

static inline UIColor *SNSystemBlueColor(UIColor *fallback) {
    return SNInterfaceColor(@"systemBlueColor", fallback);
}

static inline UIColor *SNSystemRedColor(UIColor *fallback) {
    return SNInterfaceColor(@"systemRedColor", fallback);
}

static inline UIColor *SNSystemGreenColor(UIColor *fallback) {
    return SNInterfaceColor(@"systemGreenColor", fallback);
}

static inline UIColor *SNLegacyTextShadowColor(UIColor *fallback) {
    return SNSupportsSemanticColors() ? nil : fallback;
}

#endif
