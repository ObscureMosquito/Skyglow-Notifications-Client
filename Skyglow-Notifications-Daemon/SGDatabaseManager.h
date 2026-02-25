#ifndef SKYGLOW_SG_DATABASE_MANAGER_H
#define SKYGLOW_SG_DATABASE_MANAGER_H

#import <Foundation/Foundation.h>

@interface SGDatabaseManager : NSObject

/// The thread-safe shared instance of the database manager.
+ (SGDatabaseManager *)sharedManager;

// --- Token & Identity Management ---

- (BOOL)storeDeviceTokenData:(NSData *)routingKey
                     e2eeKey:(NSData *)e2eeKey
                    bundleID:(NSString *)bundleID
                       token:(NSData *)token
                  isUploaded:(BOOL)isUploaded;

- (NSArray *)pendingUploadTokens;
- (BOOL)markTokenAsUploaded:(NSData *)routingKey;
- (void)resetAllTokensToRequireUpload;
- (NSDictionary *)tokenDataForRoutingKey:(NSData *)routingKey;
- (NSArray *)tokenEntriesForBundleIdentifier:(NSString *)bundleID;
- (BOOL)removeTokenForBundleIdentifier:(NSString *)bundleID;
- (NSArray *)allActiveRoutingKeys;
- (NSSet *)registeredBundleIdentifiers;

// --- Connectivity & Synchronization ---

- (NSDictionary *)cachedDNSForDomain:(NSString *)domain maxAge:(NSTimeInterval)maxAge;
- (BOOL)storeDNSCacheForDomain:(NSString *)domain ip:(NSString *)ip port:(NSString *)port;
- (BOOL)enqueueAcknowledgementForMessageID:(NSData *)msgID status:(int)status;
- (NSArray *)pendingAcknowledgements;
- (BOOL)removeAcknowledgementForMessageID:(NSData *)msgID;

// --- Daemon Settings ---
- (void)saveKeepAliveInterval:(double)interval forWiFi:(BOOL)isWiFi;
- (double)loadKeepAliveIntervalForWiFi:(BOOL)isWiFi;

- (void)closeDatabase;

@end

#endif /* SKYGLOW_SG_DATABASE_MANAGER_H */