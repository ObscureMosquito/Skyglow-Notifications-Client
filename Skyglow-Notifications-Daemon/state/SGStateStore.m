#import "SGStateStore.h"
#import "SGStorage.h"
#import "SGConfiguration.h"
#import "SGDatabaseManager.h"
#import "SGTokenManager.h"
#import "SGControlChannelProtocol.h"
#import "SGStatusServer.h"
#import "SGProtocolHandler.h"
#import "SGLog.h"
#import "SGLogDiagnostics.h"

@implementation SGStateStore {
    dispatch_queue_t _storageQueue;
}

- (id)init {
    if ((self = [super init])) {
        _storageQueue = dispatch_queue_create("com.skyglow.daemon.storage",
                                               DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)dealloc {
    if (_storageQueue) dispatch_release(_storageQueue);
    [super dealloc];
}

#pragma mark - Main-prefs write choke point

- (BOOL)updateMainPreferences:
    (void (^)(NSMutableDictionary *preferences))mutation {
    if (!mutation) return NO;
    @synchronized(self) {
        NSString *plistPath = SGPath(SG_PREFS_PLIST_PATH);
        NSMutableDictionary *preferences =
            [NSMutableDictionary dictionaryWithContentsOfFile:plistPath]
            ?: [NSMutableDictionary dictionary];
        mutation(preferences);
        return SGAtomicWritePropertyList(preferences, plistPath, 0644, NULL);
    }
}

- (BOOL)_writeAppStatus:(BOOL)enabled forBundleIdentifier:(NSString *)bundleID {
    if (![bundleID length]) return NO;
    return [self updateMainPreferences:^(NSMutableDictionary *preferences) {
        NSMutableDictionary *appStatus =
            [NSMutableDictionary dictionaryWithDictionary:
                [preferences objectForKey:@"appStatus"] ?: @{}];
        [appStatus setObject:[NSNumber numberWithBool:enabled] forKey:bundleID];
        [preferences setObject:appStatus forKey:@"appStatus"];
    }];
}

- (BOOL)_removeAppStatusForBundleIdentifier:(NSString *)bundleID {
    if (![bundleID length]) return NO;
    return [self updateMainPreferences:^(NSMutableDictionary *preferences) {
        NSMutableDictionary *appStatus =
            [NSMutableDictionary dictionaryWithDictionary:
                [preferences objectForKey:@"appStatus"] ?: @{}];
        [appStatus removeObjectForKey:bundleID];
        [preferences setObject:appStatus forKey:@"appStatus"];
    }];
}

#pragma mark - Delete-app private helpers

- (BOOL)_runDeletionCascadeForBundleIdentifier:(NSString *)bundleID {
    if (![bundleID length]) return NO;
    return [[SGDatabaseManager sharedManager]
        removeAllStateForBundleIdentifier:bundleID];
}

#pragma mark - Per-app intents (IPC only)

- (BOOL)performSetAppEnabled:(BOOL)enabled
         forBundleIdentifier:(NSString *)bundleID {
    if (!SG_IsIdentifierStringSafe(bundleID)) return NO;

    @synchronized(self) {
        SGDatabaseManager *database = [SGDatabaseManager sharedManager];
        if (!database) return NO;

        NSDictionary *preferences = [NSDictionary dictionaryWithContentsOfFile:
            SGPath(SG_PREFS_PLIST_PATH)] ?: @{};
        id previousIntent =
            [[preferences objectForKey:@"appStatus"] objectForKey:bundleID];
        /* No persisted provider choice is fail-closed. Otherwise appStatus's
         * boolean is the durable source for the pre-request mute state. */
        BOOL rollbackMuted =
            previousIntent ? ![previousIntent boolValue] : YES;

        if (enabled) {
            SGTokenManager *tokenManager = [[SGTokenManager alloc] init];
            NSError *tokenError = nil;
            NSData *token = [tokenManager
                synchronizedTokenForBundleIdentifier:bundleID
                                               error:&tokenError];
            [tokenManager release];
            if (!token) {
                SGLOGE(SGStateStore,
                       "code=%s bundle=%s result=failed reason=%s",
                       SGND_TOKEN_GENERATE_FAILED, [bundleID UTF8String],
                       [[tokenError description] UTF8String]);
                return NO;
            }
        }

        BOOL databaseUpdated =
            [database setMuted:!enabled forBundleIdentifier:bundleID];
        BOOL intentUpdated =
            databaseUpdated &&
            [self _writeAppStatus:enabled forBundleIdentifier:bundleID];
        if (!intentUpdated) {
            [database setMuted:rollbackMuted forBundleIdentifier:bundleID];
            return NO;
        }

        SGP_FlushActiveTopicFilter();
        return YES;
    }
}

- (BOOL)performClearAppIntentForBundleIdentifier:(NSString *)bundleID {
    if (!SG_IsIdentifierStringSafe(bundleID)) return NO;

    @synchronized(self) {
        SGDatabaseManager *database = [SGDatabaseManager sharedManager];
        if (!database) return NO;

        NSDictionary *preferences = [NSDictionary dictionaryWithContentsOfFile:
            SGPath(SG_PREFS_PLIST_PATH)] ?: @{};
        id previousIntent =
            [[preferences objectForKey:@"appStatus"] objectForKey:bundleID];
        BOOL rollbackMuted =
            previousIntent ? ![previousIntent boolValue] : YES;

        BOOL databaseUpdated =
            [database setMuted:YES forBundleIdentifier:bundleID];
        BOOL intentRemoved =
            databaseUpdated &&
            [self _removeAppStatusForBundleIdentifier:bundleID];
        if (!intentRemoved) {
            if (databaseUpdated) {
                [database setMuted:rollbackMuted forBundleIdentifier:bundleID];
            }
            return NO;
        }

        SGP_FlushActiveTopicFilter();
        return YES;
    }
}

- (BOOL)performDeleteAppStateForBundleIdentifier:(NSString *)bundleID {
    if (!SG_IsIdentifierStringSafe(bundleID)) return NO;
    @synchronized(self) {
        BOOL databaseClean = [self _runDeletionCascadeForBundleIdentifier:bundleID];
        BOOL intentRemoved =
            [self _removeAppStatusForBundleIdentifier:bundleID];
        if (!(databaseClean && intentRemoved)) return NO;

        SGP_FlushActiveTopicFilter();
        return YES;
    }
}

#pragma mark - Durable missed-uninstall inbox

- (BOOL)_applyDurableEvent:(NSDictionary *)event {
    if ([[event objectForKey:SGDurableEventFormatVersionKey] integerValue] != 1) {
        return NO;
    }
    NSString *type = [event objectForKey:SGDurableEventTypeKey];
    NSString *bundleID = [event objectForKey:SGDurableEventBundleIdentifierKey];
    if (![type isKindOfClass:[NSString class]] ||
        !SG_IsIdentifierStringSafe(bundleID)) {
        return NO;
    }

    if ([type isEqualToString:SGDurableEventDeleteApp]) {
        return [self performDeleteAppStateForBundleIdentifier:bundleID];
    }
    return NO;
}

- (void)drainDurableEventInbox {
    dispatch_async(_storageQueue, ^{
        @autoreleasepool {
            NSArray *events = SGDurableEventPendingEvents(
                SGPath(SG_DURABLE_EVENT_INBOX_PATH));
            NSMutableSet *blockedBundles = [NSMutableSet set];
            for (NSDictionary *event in events) {
                NSString *type = [event objectForKey:SGDurableEventTypeKey];
                NSString *bundleID =
                    [event objectForKey:SGDurableEventBundleIdentifierKey];
                BOOL knownType =
                    [type isEqualToString:SGDurableEventDeleteApp];
                BOOL structurallyValid =
                    [[event objectForKey:SGDurableEventFormatVersionKey]
                        integerValue] == 1 &&
                    [type isKindOfClass:[NSString class]] &&
                    SG_IsIdentifierStringSafe(bundleID) &&
                    knownType;
                if (!structurallyValid) {
                    SGLOGE(SGStateStore, "code=%s file=%s action=quarantine",
                           SGND_DURABLE_EVENT_INVALID,
                           [[[event objectForKey:SGDurableEventFilePathKey]
                               lastPathComponent] UTF8String]);
                    SGDurableEventQuarantine(event);
                    continue;
                }

                /* Preserve ordering for repeated uninstall records for one app
                 * without blocking an unrelated app's uninstall cleanup. */
                if ([blockedBundles containsObject:bundleID]) continue;

                if ([self _applyDurableEvent:event]) {
                    SGDurableEventRemove(event);
                    SGLOGI(SGStateStore, "code=%s type=%s bundle=%s",
                           SGND_DURABLE_EVENT_APPLIED, [type UTF8String],
                           [bundleID UTF8String]);
                } else {
                    SGLOGW(SGStateStore, "code=%s type=%s bundle=%s action=retry_later",
                           SGND_DURABLE_EVENT_DEFERRED, [type UTF8String],
                           [bundleID UTF8String]);
                    [blockedBundles addObject:bundleID];
                }
            }
        }
    });
}

@end
