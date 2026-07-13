#import "SGStateStore.h"
#import "SGAtomicFile.h"
#import "SGDurableInbox.h"
#import "SGConfiguration.h"
#import "SGDatabaseManager.h"
#import "SGKeychainStore.h"
#import "SGTokenManager.h"
#import "SGControlChannelProtocol.h"
#import "SGStatusServer.h"
#import "SGProtocolHandler.h"
#import "SGLog.h"
#import "SGLogDiagnostics.h"
#include <unistd.h>

static NSString * const kSGProfileCertificateDirectory =
    @"/var/mobile/Library/SkyglowNotifications";

/* System-root-relative (wrap with SGPath before touching disk), matching how
 * the plist's server_pub_key value has always been stored. */
static NSString *SGProfileCertificatePathForIndex(NSInteger profileIdx) {
    return [NSString stringWithFormat:@"%@/profile%ld-server.pem",
            kSGProfileCertificateDirectory, (long)profileIdx];
}

static NSString *SGProfilePlistPathForIndex(NSInteger profileIdx) {
    return SGPath([NSString stringWithFormat:
        SG_PROFILE_PLIST_FORMAT, (long)profileIdx]);
}

static BOOL SGProfileIndexIsValid(NSInteger profileIdx) {
    return profileIdx >= 1 && profileIdx <= 5;
}

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

#pragma mark - Profile-slot persistence choke points

- (BOOL)_updateProfileAtIndex:(NSInteger)profileIdx
                     mutation:(void (^)(NSMutableDictionary *profile))mutation {
    if (!SGProfileIndexIsValid(profileIdx) || !mutation) return NO;
    @synchronized(self) {
        NSString *plistPath = SGProfilePlistPathForIndex(profileIdx);
        NSMutableDictionary *profile =
            [NSMutableDictionary dictionaryWithContentsOfFile:plistPath]
            ?: [NSMutableDictionary dictionary];
        mutation(profile);
        return SGAtomicWritePropertyList(profile, plistPath, 0644, NULL);
    }
}

- (BOOL)commitRegistrationForProfileAtIndex:(NSInteger)profileIdx
                              deviceAddress:(NSString *)deviceAddress
                              privateKeyPEM:(NSString *)privateKeyPEM {
    if (!SGProfileIndexIsValid(profileIdx) ||
        ![deviceAddress length] || ![privateKeyPEM length]) {
        SGLOGE(SGStateStore, "code=%s profile=%ld result=rejected reason=invalid_input",
               SGND_REGISTRATION_KEY_WRITE_FAILED, (long)profileIdx);
        return NO;
    }
    @synchronized(self) {
        if (!SGKeychain_StorePrivateKeyPEM(privateKeyPEM, profileIdx)) {
            SGLOGE(SGStateStore, "code=%s profile=%ld result=failed",
                   SGND_REGISTRATION_KEY_WRITE_FAILED, (long)profileIdx);
            return NO;
        }
        BOOL persisted = [self _updateProfileAtIndex:profileIdx
                                            mutation:^(NSMutableDictionary *profile) {
            [profile setObject:deviceAddress forKey:@"device_address"];
        }];
        if (!persisted) {
            SGKeychain_DeletePrivateKey(profileIdx);
            return NO;
        }
        return YES;
    }
}

- (BOOL)wipeProfileCredentialsAtIndex:(NSInteger)profileIdx {
    if (!SGProfileIndexIsValid(profileIdx)) return NO;
    @synchronized(self) {
        SGKeychain_DeletePrivateKey(profileIdx);
        return [self _updateProfileAtIndex:profileIdx
                                  mutation:^(NSMutableDictionary *profile) {
            [profile removeObjectForKey:@"device_address"];
            [profile removeObjectForKey:@"privateKey"];
        }];
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
                if (previousCertData) {
                    SGAtomicWriteData(previousCertData, certDiskPath, 0644, NULL);
                } else {
                    unlink([certDiskPath fileSystemRepresentation]);
                }
            }
            return NO;
        }

        if (invalidate) SGKeychain_DeletePrivateKey(profileIdx);
        if (outInvalidatedCredentials) *outInvalidatedCredentials = invalidate;
        return YES;
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
            !SGKeychain_CopyPrivateKeyPEM(profileIdx, &keySnapshot)) {
            if (keySnapshot) {
                [keySnapshot resetBytesInRange:NSMakeRange(0, [keySnapshot length])];
            }
            return NO;
        }

        NSError *removeError = nil;
        BOOL ok = SGDurableRemoveItem(plistPath, &removeError) &&
                  SGDurableRemoveItem(certDiskPath, &removeError) &&
                  SGKeychain_DeletePrivateKey(profileIdx) &&
                  [[SGDatabaseManager sharedManager]
                      clearOperationalStateForProfile:profileIdx];

        if (!ok) {
            BOOL rollbackOK = YES;
            if (hadCertificate) {
                rollbackOK = SGAtomicWriteData(
                    certificateSnapshot, certDiskPath, 0644, NULL) && rollbackOK;
            }
            if (keySnapshot) {
                rollbackOK = SGKeychain_StorePrivateKeyData(
                    keySnapshot, profileIdx) && rollbackOK;
            }
            if (hadProfile) {
                rollbackOK = SGAtomicWriteData(
                    profileSnapshot, plistPath, 0644, NULL) && rollbackOK;
            }
            SGLOGE(SGStateStore,
                   "profile-delete: commit failed idx=%ld rollback=%s error=%s",
                   (long)profileIdx,
                   rollbackOK ? "ok" : "failed",
                   removeError ? [[removeError description] UTF8String] : "none");
        }

        if (keySnapshot) {
            [keySnapshot resetBytesInRange:NSMakeRange(0, [keySnapshot length])];
        }
        return ok;
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

        NSDictionary *preferences = [NSDictionary dictionaryWithContentsOfFile:
            SGPath(SG_PREFS_PLIST_PATH)] ?: @{};
        id previousIntent =
            [[preferences objectForKey:@"appStatus"] objectForKey:bundleID];
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
        NSDictionary *preferences = [NSDictionary dictionaryWithContentsOfFile:
            SGPath(SG_PREFS_PLIST_PATH)] ?: @{};
        id previousIntent =
            [[preferences objectForKey:@"appStatus"] objectForKey:bundleID];

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

                if ([blockedBundles containsObject:bundleID]) continue;

                BOOL applied = NO;
                BOOL superseded = NO;
                @synchronized(self) {
                    NSString *eventPath =
                        [event objectForKey:SGDurableEventFilePathKey];
                    if (access([eventPath fileSystemRepresentation],
                               F_OK) != 0) {
                        superseded = YES;
                    } else {
                        applied = [self _applyDurableEvent:event];
                    }
                }
                if (superseded) continue;

                if (applied) {
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
