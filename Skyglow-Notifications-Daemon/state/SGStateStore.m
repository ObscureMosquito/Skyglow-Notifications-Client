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

#pragma mark - Pending-deletion + DB cascade

- (BOOL)runDeletionCascadeForBundleIdentifier:(NSString *)bundleID {
    if (![bundleID length]) return NO;
    return [[SGDatabaseManager sharedManager]
        removeAllStateForBundleIdentifier:bundleID];
}

- (BOOL)clearPendingDeletionForBundleIdentifier:(NSString *)bundleID {
    if (![bundleID length]) return NO;
    return [self clearPendingDeletionsForBundleIdentifiers:@[bundleID]];
}

- (BOOL)clearPendingDeletionsForBundleIdentifiers:(NSArray *)bundles {
    if ([bundles count] == 0) return YES;
    return [self updateMainPreferences:^(NSMutableDictionary *preferences) {
        NSArray *current = [preferences objectForKey:@"pendingDeletions"];
        if ([current count] == 0) return;
        NSMutableArray *next = [NSMutableArray arrayWithArray:current];
        [next removeObjectsInArray:bundles];
        [preferences setObject:next forKey:@"pendingDeletions"];
    }];
}

#pragma mark - Per-app intents (shared by IPC + durable inbox)

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
        [self schedulePublicStateSnapshot];
        return YES;
    }
}

- (BOOL)performClearAppIntentForBundleIdentifier:(NSString *)bundleID {
    if (!SG_IsIdentifierStringSafe(bundleID)) return NO;
    BOOL removed = [self _removeAppStatusForBundleIdentifier:bundleID];
    if (removed) [self schedulePublicStateSnapshot];
    return removed;
}

- (BOOL)performDeleteAppStateForBundleIdentifier:(NSString *)bundleID {
    if (!SG_IsIdentifierStringSafe(bundleID)) return NO;
    @synchronized(self) {
        BOOL databaseClean = [self runDeletionCascadeForBundleIdentifier:bundleID];
        BOOL pendingCleared =
            [self clearPendingDeletionForBundleIdentifier:bundleID];
        BOOL intentRemoved =
            [self _removeAppStatusForBundleIdentifier:bundleID];
        if (!(databaseClean && pendingCleared && intentRemoved)) return NO;

        SGP_FlushActiveTopicFilter();
        [self schedulePublicStateSnapshot];
        return YES;
    }
}

#pragma mark - Public read-model snapshot

- (BOOL)_writePublicStateSnapshot {
    NSDictionary *preferences = [NSDictionary dictionaryWithContentsOfFile:
        SGPath(SG_PREFS_PLIST_PATH)] ?: @{};
    NSDictionary *previous = [NSDictionary dictionaryWithContentsOfFile:
        SGPath(SG_PUBLIC_STATE_PATH)];
    unsigned long long generation =
        [[previous objectForKey:@"generation"] unsignedLongLongValue] + 1;

    NSMutableDictionary *snapshot = [NSMutableDictionary dictionary];
    [snapshot setObject:[NSNumber numberWithInteger:1] forKey:@"formatVersion"];
    [snapshot setObject:[NSNumber numberWithUnsignedLongLong:generation]
                 forKey:@"generation"];
    [snapshot setObject:[NSNumber numberWithDouble:
        ([[NSDate date] timeIntervalSince1970])] forKey:@"updatedAt"];

    for (NSString *key in @[
            @"enabled", @"activeProfile", @"logLevel", @"appStatus"]) {
        id value = [preferences objectForKey:key];
        if (value) [snapshot setObject:value forKey:key];
    }

    NSArray *registered = [[[[SGDatabaseManager sharedManager]
        registeredBundleIdentifiers] allObjects]
        sortedArrayUsingSelector:@selector(compare:)];
    [snapshot setObject:registered ?: @[] forKey:@"registeredBundleIDs"];

    SGStatusPayload status;
    memset(&status, 0, sizeof(status));
    SGStatusServer_Current(&status);
    NSString *serverIP = [NSString stringWithUTF8String:status.serverIP] ?: @"";
    NSString *errorDetail =
        [NSString stringWithUTF8String:status.errorDetail] ?: @"";
    NSDictionary *statusDictionary = @{
        @"state": [NSNumber numberWithUnsignedInt:status.state],
        @"consecutiveFailures":
            [NSNumber numberWithUnsignedInt:status.consecutiveFailures],
        @"currentBackoffSec":
            [NSNumber numberWithUnsignedInt:status.currentBackoffSec],
        @"serverIP": serverIP,
        @"daemonStartTime":
            [NSNumber numberWithLongLong:status.daemonStartTime],
        @"lastStateTransitionTime":
            [NSNumber numberWithLongLong:status.lastStateTransitionTime],
        @"errorDetail": errorDetail,
        @"activeProfileIndex":
            [NSNumber numberWithUnsignedInt:status.activeProfileIndex],
    };
    [snapshot setObject:statusDictionary forKey:@"status"];

    NSError *error = nil;
    BOOL written = SGAtomicWritePropertyList(snapshot,
        SGPath(SG_PUBLIC_STATE_PATH), 0644, &error);
    if (!written) {
        SGLOGE(SGStateStore, "code=%s reason=%s",
               SGND_PUBLIC_STATE_WRITE_FAILED,
               [[error description] UTF8String]);
    }
    return written;
}

- (void)schedulePublicStateSnapshot {
    dispatch_async(_storageQueue, ^{
        @autoreleasepool {
            [self _writePublicStateSnapshot];
        }
    });
}

#pragma mark - Durable write-ahead inbox

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

    if ([type isEqualToString:SGDurableEventSetAppEnabled]) {
        NSNumber *enabled = [event objectForKey:SGDurableEventEnabledKey];
        if (![enabled isKindOfClass:[NSNumber class]]) return NO;
        return [self performSetAppEnabled:[enabled boolValue]
                      forBundleIdentifier:bundleID];
    }
    if ([type isEqualToString:SGDurableEventClearAppIntent]) {
        return [self performClearAppIntentForBundleIdentifier:bundleID];
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
                    [type isEqualToString:SGDurableEventSetAppEnabled] ||
                    [type isEqualToString:SGDurableEventClearAppIntent] ||
                    [type isEqualToString:SGDurableEventDeleteApp];
                BOOL payloadValid =
                    ![type isEqualToString:SGDurableEventSetAppEnabled] ||
                    [[event objectForKey:SGDurableEventEnabledKey]
                        isKindOfClass:[NSNumber class]];
                BOOL structurallyValid =
                    [[event objectForKey:SGDurableEventFormatVersionKey]
                        integerValue] == 1 &&
                    [type isKindOfClass:[NSString class]] &&
                    SG_IsIdentifierStringSafe(bundleID) &&
                    knownType && payloadValid;
                if (!structurallyValid) {
                    SGLOGE(SGStateStore, "code=%s file=%s action=quarantine",
                           SGND_DURABLE_EVENT_INVALID,
                           [[[event objectForKey:SGDurableEventFilePathKey]
                               lastPathComponent] UTF8String]);
                    SGDurableEventQuarantine(event);
                    continue;
                }

                /* Preserve ordering for repeated choices concerning one app,
                 * without allowing a temporarily uncommittable registration
                 * to block an unrelated app's uninstall cleanup. */
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
