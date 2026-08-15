#import "SGStateStore.h"
#import "SGStorage.h"
#import "SGDurableInbox.h"
#import "SGConfiguration.h"
#import "SGDatabaseManager.h"
#import "SGPlatform.h"
#import "SGTokenManager.h"
#import "SGControlChannelProtocol.h"
#import "SGStatus.h"
#import "SGProtocolHandler.h"
#import "SGCryptoEngine.h"
#import "SGLog.h"
#import "SGLogDiagnostics.h"
#include <unistd.h>

#define SG_DURABLE_EVENT_TTL_SECONDS (30.0 * 86400.0)

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

static BOOL SGUpdatePlistAtPath(NSString *plistPath,
                                void (^mutation)(NSMutableDictionary *)) {
    NSMutableDictionary *contents =
        [NSMutableDictionary dictionaryWithContentsOfFile:plistPath]
        ?: [NSMutableDictionary dictionary];
    mutation(contents);
    return SGAtomicWritePropertyList(contents, plistPath, 0644, NULL);
}

static BOOL SGRestoreFileSnapshot(NSString *path, NSData *snapshot, mode_t mode) {
    if (snapshot) return SGAtomicWriteData(snapshot, path, mode, NULL);
    return SGDurableRemoveItem(path, NULL);
}

#pragma mark - Configuration ownership

- (void)_republishConfigurationLocked {
    [[SGConfiguration sharedConfiguration] reloadFromDisk];
}

- (void)reloadConfiguration {
    @synchronized(self) {
        [self _republishConfigurationLocked];
    }
}

- (void)reconcileTokensWithDatabase {
    @synchronized(self) {
        NSDictionary *preferences = [NSDictionary dictionaryWithContentsOfFile:
            SGPath(SG_PREFS_PLIST_PATH)] ?: @{};
        NSDictionary *appStatus =
            [preferences objectForKey:SG_PREFS_KEY_APP_STATUS] ?: @{};
        SGDatabaseManager *db = [SGDatabaseManager sharedManager];

        NSMutableSet *optedIn  = [NSMutableSet set];
        NSMutableSet *optedOut = [NSMutableSet set];
        for (NSString *bundleID in appStatus) {
            if ([[appStatus objectForKey:bundleID] boolValue]) {
                [optedIn addObject:bundleID];
            } else {
                [optedOut addObject:bundleID];
            }
        }

        NSSet *dbBundles = [db registeredBundleIdentifiers];
        for (NSString *bundleID in dbBundles) {
            if ([optedIn containsObject:bundleID]) {
                [db setMuted:NO forBundleIdentifier:bundleID];
            } else if ([optedOut containsObject:bundleID]) {
                [db setMuted:YES forBundleIdentifier:bundleID];
            }
        }

        NSMutableSet *allIntents = [NSMutableSet setWithSet:optedIn];
        [allIntents unionSet:optedOut];
        NSString *serverAddress =
            [[SGConfiguration sharedConfiguration] serverAddress];
        BOOL mutated = NO;

        if ([serverAddress length] > 0) {
            SGTokenManager *tokenManager = [[SGTokenManager alloc] init];
            for (NSString *bundleID in allIntents) {
                if ([dbBundles containsObject:bundleID]) continue;
                NSError *tokenError = nil;
                NSData *token = [tokenManager
                    synchronizedTokenForBundleIdentifier:bundleID
                                                   error:&tokenError];
                if (token) {
                    SGLOGI(SGStateStore, "code=%s bundle=%s result=generated",
                           SGND_TOKEN_MISSING_GENERATED, [bundleID UTF8String]);
                    if ([optedOut containsObject:bundleID]) {
                        [db setMuted:YES forBundleIdentifier:bundleID];
                    }
                    mutated = YES;
                } else {
                    SGLOGE(SGStateStore, "code=%s bundle=%s result=failed reason=%s",
                           SGND_TOKEN_GENERATE_FAILED, [bundleID UTF8String],
                           [[tokenError description] UTF8String]);
                }
            }
            [tokenManager release];
        } else {
            for (NSString *bundleID in allIntents) {
                if (![dbBundles containsObject:bundleID]) {
                    SGLOGI(SGStateStore, "code=%s bundle=%s action=defer_until_registration",
                           SGND_TOKEN_DEFER_UNREGISTERED, [bundleID UTF8String]);
                }
            }
        }

        if (mutated) SGP_FlushActiveTopicFilter();
    }
}

#pragma mark - Main-prefs choke points

- (BOOL)updateMainPreferences:
    (void (^)(NSMutableDictionary *preferences))mutation {
    if (!mutation) return NO;
    @synchronized(self) {
        BOOL persisted = SGUpdatePlistAtPath(SGPath(SG_PREFS_PLIST_PATH), mutation);
        if (persisted) [self _republishConfigurationLocked];
        return persisted;
    }
}

- (NSDictionary *)appStatusDictionary {
    @synchronized(self) {
        NSDictionary *preferences = [NSDictionary dictionaryWithContentsOfFile:
            SGPath(SG_PREFS_PLIST_PATH)] ?: @{};
        return [preferences objectForKey:SG_PREFS_KEY_APP_STATUS] ?: @{};
    }
}

- (id)_appIntentForBundleIdentifier:(NSString *)bundleID {
    return [[self appStatusDictionary] objectForKey:bundleID];
}

- (BOOL)_writeAppStatus:(BOOL)enabled forBundleIdentifier:(NSString *)bundleID {
    if (![bundleID length]) return NO;
    return [self updateMainPreferences:^(NSMutableDictionary *preferences) {
        NSMutableDictionary *appStatus =
            [NSMutableDictionary dictionaryWithDictionary:
                [preferences objectForKey:SG_PREFS_KEY_APP_STATUS] ?: @{}];
        [appStatus setObject:[NSNumber numberWithBool:enabled] forKey:bundleID];
        [preferences setObject:appStatus forKey:SG_PREFS_KEY_APP_STATUS];
    }];
}

- (BOOL)_removeAppStatusForBundleIdentifier:(NSString *)bundleID {
    if (![bundleID length]) return NO;
    return [self updateMainPreferences:^(NSMutableDictionary *preferences) {
        NSMutableDictionary *appStatus =
            [NSMutableDictionary dictionaryWithDictionary:
                [preferences objectForKey:SG_PREFS_KEY_APP_STATUS] ?: @{}];
        [appStatus removeObjectForKey:bundleID];
        [preferences setObject:appStatus forKey:SG_PREFS_KEY_APP_STATUS];
    }];
}

#pragma mark - Profile-slot persistence choke points

- (BOOL)_updateProfileAtIndex:(NSInteger)profileIdx
                     mutation:(void (^)(NSMutableDictionary *profile))mutation {
    if (!SGProfileIndexIsValid(profileIdx) || !mutation) return NO;
    @synchronized(self) {
        return SGUpdatePlistAtPath(SGProfilePlistPathForIndex(profileIdx), mutation);
    }
}

- (BOOL)commitRegistrationForProfileAtIndex:(NSInteger)profileIdx
                              deviceAddress:(NSString *)deviceAddress
                              privateKeyPEM:(NSData *)privateKeyPEM {
    if (!SGProfileIndexIsValid(profileIdx) ||
        ![deviceAddress length] || ![privateKeyPEM length]) {
        SGLOGE(SGStateStore, "code=%s profile=%ld result=rejected reason=invalid_input",
               SGND_REGISTRATION_KEY_WRITE_FAILED, (long)profileIdx);
        return NO;
    }
    @synchronized(self) {
        if (![[SGPlatform currentPlatform].keyStore storeKeyData:privateKeyPEM forProfile:profileIdx]) {
            SGLOGE(SGStateStore, "code=%s profile=%ld result=failed",
                   SGND_REGISTRATION_KEY_WRITE_FAILED, (long)profileIdx);
            return NO;
        }

        NSMutableData *verifyKey = nil;
        if (![[SGPlatform currentPlatform].keyStore copyKeyData:&verifyKey forProfile:profileIdx] || !verifyKey || [verifyKey length] == 0) {
            SGLOGE(SGStateStore, "code=%s profile=%ld result=failed reason=readback_failed",
                   SGND_REGISTRATION_KEY_WRITE_FAILED, (long)profileIdx);
            [[SGPlatform currentPlatform].keyStore deleteKeyForProfile:profileIdx];
            if (verifyKey) SG_CryptoWipeData(verifyKey);
            return NO;
        }
        SG_CryptoWipeData(verifyKey);

        BOOL persisted = [self _updateProfileAtIndex:profileIdx
                                            mutation:^(NSMutableDictionary *profile) {
            [profile setObject:deviceAddress forKey:@"device_address"];
            [profile removeObjectForKey:@"last_reg_fail"];
        }];
        if (!persisted) {
            [[SGPlatform currentPlatform].keyStore deleteKeyForProfile:profileIdx];
            return NO;
        }

        [self _republishConfigurationLocked];
        return YES;
    }
}

- (BOOL)wipeProfileCredentialsAtIndex:(NSInteger)profileIdx {
    if (!SGProfileIndexIsValid(profileIdx)) return NO;
    @synchronized(self) {
        BOOL persisted = [self _updateProfileAtIndex:profileIdx
                                            mutation:^(NSMutableDictionary *profile) {
            [profile removeObjectForKey:@"device_address"];
            [profile removeObjectForKey:@"privateKey"];
            [profile removeObjectForKey:@"last_reg_fail"];
        }];
        [[SGPlatform currentPlatform].keyStore deleteKeyForProfile:profileIdx];
        if (persisted) [self _republishConfigurationLocked];
        return persisted;
    }
}

- (void)confirmRegistrationForProfileAtIndex:(NSInteger)profileIdx {
    if (!SGProfileIndexIsValid(profileIdx)) return;
    @synchronized(self) {
        NSDictionary *profile = [NSDictionary dictionaryWithContentsOfFile:
            SGProfilePlistPathForIndex(profileIdx)] ?: @{};
        if (![[profile objectForKey:@"device_address"] length] ||
            ![profile objectForKey:@"registration_identity"]) {
            return;
        }
        SGDurableRemoveItem(SGPath(SGProfileRegIdentityPathForIndex(profileIdx)), NULL);
        [self _updateProfileAtIndex:profileIdx
                           mutation:^(NSMutableDictionary *p) {
            [p removeObjectForKey:@"registration_identity"];
        }];
        [self _republishConfigurationLocked];
    }
}

- (BOOL)saveProfileAtIndex:(NSInteger)profileIdx
             serverAddress:(NSString *)serverAddress
            certificatePEM:(NSString *)certificatePEM
    invalidatedCredentials:(BOOL *)outInvalidatedCredentials {
    if (outInvalidatedCredentials) *outInvalidatedCredentials = NO;
    if (!SGProfileIndexIsValid(profileIdx) || ![serverAddress length]) return NO;

    @synchronized(self) {
        SGEnsureRuntimeDirectories();

        NSString *storedCertPath = SGProfileCertificatePathForIndex(profileIdx);
        NSString *certDiskPath = SGPath(storedCertPath);

        NSDictionary *existing = [NSDictionary dictionaryWithContentsOfFile:
            SGProfilePlistPathForIndex(profileIdx)] ?: @{};
        NSString *oldAddress = [existing objectForKey:@"server_address"];
        NSString *oldCertPath = [existing objectForKey:@"server_pub_key"];

        BOOL hasNewCertificate = ([certificatePEM length] > 0);
        NSData *previousCertData = [NSData dataWithContentsOfFile:certDiskPath];
        BOOL certFileReplaced = NO;

        if (hasNewCertificate) {
            NSData *pemData =
                [certificatePEM dataUsingEncoding:NSUTF8StringEncoding];
            if (!SGAtomicWriteData(pemData, certDiskPath, 0644, NULL)) return NO;
            certFileReplaced = YES;
        } else if ([oldCertPath isEqualToString:storedCertPath] &&
                   access([certDiskPath fileSystemRepresentation],
                          F_OK) == 0) {
        } else {
            return NO;
        }

        BOOL addressChanged =
            (oldAddress && ![oldAddress isEqualToString:serverAddress]);
        BOOL invalidate = addressChanged || hasNewCertificate;

        BOOL persisted = [self _updateProfileAtIndex:profileIdx
                                            mutation:^(NSMutableDictionary *profile) {
            [profile setObject:serverAddress forKey:@"server_address"];
            [profile setObject:storedCertPath forKey:@"server_pub_key"];
            if (invalidate) {
                [profile removeObjectForKey:@"device_address"];
                [profile removeObjectForKey:@"privateKey"];
            }
        }];
        if (!persisted) {
            if (certFileReplaced) {
                SGRestoreFileSnapshot(certDiskPath, previousCertData, 0644);
            }
            return NO;
        }

        if (invalidate) {
            [[SGPlatform currentPlatform].keyStore deleteKeyForProfile:profileIdx];
            [[SGDatabaseManager sharedManager]
                clearOperationalStateForProfile:profileIdx];
        } else if (addressChanged) {
            [[SGDatabaseManager sharedManager] clearDNSCacheForProfile:profileIdx];
        }
        if (outInvalidatedCredentials) *outInvalidatedCredentials = invalidate;
        [self _republishConfigurationLocked];
        return YES;
    }
}

- (BOOL)setLastRegistrationFailureCode:(uint8_t)code atIndex:(NSInteger)profileIdx {
    if (!SGProfileIndexIsValid(profileIdx)) return NO;
    @synchronized(self) {
        return [self _updateProfileAtIndex:profileIdx
                                  mutation:^(NSMutableDictionary *profile) {
            [profile setObject:[NSNumber numberWithUnsignedChar:code]
                        forKey:@"last_reg_fail"];
        }];
    }
}

- (BOOL)setRegistrationIdentityAtIndex:(NSInteger)profileIdx
                           identityPEM:(NSString *)identityPEM {
    if (!SGProfileIndexIsValid(profileIdx)) return NO;

    @synchronized(self) {
        NSString *plistPath = SGProfilePlistPathForIndex(profileIdx);
        if (![[NSFileManager defaultManager] fileExistsAtPath:plistPath]) return NO;

        NSString *storedPath = SGProfileRegIdentityPathForIndex(profileIdx);
        NSString *diskPath = SGPath(storedPath);

        BOOL persisted;
        if ([identityPEM length] > 0) {
            SGEnsureRuntimeDirectories();
            NSData *pemData = [identityPEM dataUsingEncoding:NSUTF8StringEncoding];
            if (!SGAtomicWriteData(pemData, diskPath, 0600, NULL)) return NO;
            persisted = [self _updateProfileAtIndex:profileIdx
                                          mutation:^(NSMutableDictionary *profile) {
                [profile setObject:storedPath forKey:@"registration_identity"];
                [profile removeObjectForKey:@"last_reg_fail"];
            }];
        } else {
            persisted = [self _updateProfileAtIndex:profileIdx
                                          mutation:^(NSMutableDictionary *profile) {
                [profile removeObjectForKey:@"registration_identity"];
            }];
            if (persisted) SGDurableRemoveItem(diskPath, NULL);
        }
        if (persisted) [self _republishConfigurationLocked];
        return persisted;
    }
}

- (BOOL)removeProfileAtIndex:(NSInteger)profileIdx {
    if (!SGProfileIndexIsValid(profileIdx)) return NO;
    @synchronized(self) {
        NSString *plistPath = SGProfilePlistPathForIndex(profileIdx);
        NSString *certDiskPath =
            SGPath(SGProfileCertificatePathForIndex(profileIdx));
        NSFileManager *fm = [NSFileManager defaultManager];

        BOOL hadProfile = [fm fileExistsAtPath:plistPath];
        BOOL hadCertificate = [fm fileExistsAtPath:certDiskPath];
        NSData *profileSnapshot = hadProfile
            ? [NSData dataWithContentsOfFile:plistPath] : nil;
        NSData *certificateSnapshot = hadCertificate
            ? [NSData dataWithContentsOfFile:certDiskPath] : nil;
        NSMutableData *keySnapshot = nil;

        if ((hadProfile && !profileSnapshot) ||
            (hadCertificate && !certificateSnapshot) ||
            ![[SGPlatform currentPlatform].keyStore copyKeyData:&keySnapshot forProfile:profileIdx]) {
            if (keySnapshot) {
                SG_CryptoWipeData(keySnapshot);
            }
            return NO;
        }

        NSError *removeError = nil;
        BOOL ok = SGDurableRemoveItem(plistPath, &removeError) &&
                  SGDurableRemoveItem(certDiskPath, &removeError) &&
                  [[SGPlatform currentPlatform].keyStore deleteKeyForProfile:profileIdx] &&
                  [[SGDatabaseManager sharedManager]
                      clearOperationalStateForProfile:profileIdx];

        if (!ok) {
            BOOL rollbackOK = YES;
            if (hadCertificate) {
                rollbackOK = SGRestoreFileSnapshot(
                    certDiskPath, certificateSnapshot, 0644) && rollbackOK;
            }
            if (keySnapshot) {
                rollbackOK = [[SGPlatform currentPlatform].keyStore
                    storeKeyData:keySnapshot forProfile:profileIdx] && rollbackOK;
            }
            if (hadProfile) {
                rollbackOK = SGRestoreFileSnapshot(
                    plistPath, profileSnapshot, 0644) && rollbackOK;
            }
            SGLOGE(SGStateStore,
                   "profile-delete: commit failed idx=%ld rollback=%s error=%s",
                   (long)profileIdx,
                   rollbackOK ? "ok" : "failed",
                   removeError ? [[removeError description] UTF8String] : "none");
        }

        if (keySnapshot) {
            SG_CryptoWipeData(keySnapshot);
        }
        if (ok) {
            SGDurableRemoveItem(SGPath(SGProfileRegIdentityPathForIndex(profileIdx)), NULL);

            NSDictionary *preferences = [NSDictionary dictionaryWithContentsOfFile:
                SGPath(SG_PREFS_PLIST_PATH)] ?: @{};
            if ([[preferences objectForKey:@"activeProfile"] integerValue] == profileIdx) {
                NSInteger nextActive = 1;
                for (NSInteger i = 1; i <= SG_PROFILE_INDEX_MAX; i++) {
                    if (i != profileIdx && [fm fileExistsAtPath:SGProfilePlistPathForIndex(i)]) {
                        nextActive = i;
                        break;
                    }
                }
                SGUpdatePlistAtPath(SGPath(SG_PREFS_PLIST_PATH),
                                    ^(NSMutableDictionary *preferences) {
                    [preferences setObject:[NSNumber numberWithInteger:nextActive]
                                    forKey:@"activeProfile"];
                });
            }
            [self _republishConfigurationLocked];
        }
        return ok;
    }
}

- (BOOL)setActiveProfileIndex:(NSInteger)profileIdx {
    if (!SGProfileIndexIsValid(profileIdx)) return NO;
    @synchronized(self) {
        if (![[NSFileManager defaultManager]
                fileExistsAtPath:SGProfilePlistPathForIndex(profileIdx)]) {
            return NO;
        }
        BOOL persisted = SGUpdatePlistAtPath(SGPath(SG_PREFS_PLIST_PATH),
                                             ^(NSMutableDictionary *preferences) {
            [preferences setObject:[NSNumber numberWithInteger:profileIdx]
                            forKey:@"activeProfile"];
        });
        if (persisted) [self _republishConfigurationLocked];
        return persisted;
    }
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

        id previousIntent = [self _appIntentForBundleIdentifier:bundleID];
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

        id previousIntent = [self _appIntentForBundleIdentifier:bundleID];
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
        id previousIntent = [self _appIntentForBundleIdentifier:bundleID];

        if (![self _removeAppStatusForBundleIdentifier:bundleID]) return NO;
        if (![self _runDeletionCascadeForBundleIdentifier:bundleID]) {
            BOOL rollbackOK = !previousIntent ||
                [self _writeAppStatus:[previousIntent boolValue]
                  forBundleIdentifier:bundleID];
            if (!rollbackOK) {
                SGLOGE(SGStateStore, "code=%s bundle=%s result=failed",
                       SGND_APP_DELETE_ROLLBACK_FAILED,
                       [bundleID UTF8String]);
            }
            return NO;
        }

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
            NSString *inboxPath = SGPath(SG_DURABLE_EVENT_INBOX_PATH);
            NSMutableSet *blockedBundles = [NSMutableSet set];
            NSUInteger claimed = 0;

            do {
                claimed = 0;
                for (NSDictionary *event in SGDurableEventPendingEvents(inboxPath)) {
                    NSString *type = [event objectForKey:SGDurableEventTypeKey];
                    NSString *bundleID =
                        [event objectForKey:SGDurableEventBundleIdentifierKey];
                    const char *file =
                        [[[event objectForKey:SGDurableEventFilePathKey]
                            lastPathComponent] UTF8String];

                    BOOL structurallyValid =
                        [[event objectForKey:SGDurableEventFormatVersionKey]
                            integerValue] == 1 &&
                        [type isEqualToString:SGDurableEventDeleteApp] &&
                        SG_IsIdentifierStringSafe(bundleID);
                    double createdAt =
                        [[event objectForKey:SGDurableEventCreatedAtKey] doubleValue];
                    BOOL expired = (createdAt > 0.0 &&
                        [[NSDate date] timeIntervalSince1970] - createdAt >
                            SG_DURABLE_EVENT_TTL_SECONDS);

                    if (!structurallyValid || expired) {
                        SGLOGE(SGStateStore, "code=%s file=%s action=%s",
                               SGND_DURABLE_EVENT_INVALID, file,
                               expired ? "drop_expired" : "drop_malformed");
                        SGDurableEventRemove(event);
                        claimed++;
                        continue;
                    }

                    if ([blockedBundles containsObject:bundleID]) continue;

                    /* Removing the file first is the cross-process claim: a
                     * concurrent purge either wins entirely or finds nothing. */
                    if (!SGDurableEventRemove(event)) continue;
                    claimed++;

                    BOOL applied;
                    @synchronized(self) {
                        applied = [self _applyDurableEvent:event];
                    }

                    if (applied) {
                        SGLOGI(SGStateStore, "code=%s type=%s bundle=%s",
                               SGND_DURABLE_EVENT_APPLIED, [type UTF8String],
                               [bundleID UTF8String]);
                    } else {
                        SGDurableEventEnqueueDeleteApp(inboxPath, bundleID, NULL);
                        SGLOGW(SGStateStore, "code=%s type=%s bundle=%s action=retry_later",
                               SGND_DURABLE_EVENT_DEFERRED, [type UTF8String],
                               [bundleID UTF8String]);
                        [blockedBundles addObject:bundleID];
                    }
                }
            } while (claimed > 0);
        }
    });
}

@end
