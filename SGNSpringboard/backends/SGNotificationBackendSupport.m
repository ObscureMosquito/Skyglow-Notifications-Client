#import "SGNotificationBackend.h"
#import "SGNPrivateAPI.h"

id SGNNotificationSourceForBundleIdentifier(NSString *bundleIdentifier) {
    Class sourceClass = NSClassFromString(@"UNSNotificationSourceDescription");
    id source = [sourceClass respondsToSelector:
        @selector(sourceDescriptionWithBundleIdentifier:)]
        ? [sourceClass sourceDescriptionWithBundleIdentifier:bundleIdentifier]
        : nil;
    if (source) return source;

    /* Older UserNotifications versions expose only the LaunchServices route. */
    Class proxyClass = NSClassFromString(@"LSApplicationProxy");
    id application = [proxyClass respondsToSelector:
        @selector(applicationProxyForIdentifier:)]
        ? [proxyClass applicationProxyForIdentifier:bundleIdentifier]
        : nil;
    if (!application || ![sourceClass respondsToSelector:
        @selector(applicationSourceDescriptionWithApplication:)]) {
        return nil;
    }

    source = [sourceClass applicationSourceDescriptionWithApplication:application];
    if (source) {
        NSLog(@"[SGN] Notification source resolved through LaunchServices: %@",
              bundleIdentifier);
    }
    return source;
}

NSArray *SGNFilteredSortedBundleIdentifiers(NSArray *identifiers) {
    NSMutableArray *safe = [NSMutableArray array];
    for (id candidate in identifiers ?: @[]) {
        if ([candidate isKindOfClass:[NSString class]] &&
            SG_IsIdentifierStringSafe(candidate)) {
            [safe addObject:candidate];
        }
    }
    [safe sortUsingSelector:@selector(compare:)];
    return safe;
}
