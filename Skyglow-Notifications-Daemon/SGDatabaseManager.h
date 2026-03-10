#ifndef SKYGLOW_SG_DATABASE_MANAGER_H
#define SKYGLOW_SG_DATABASE_MANAGER_H

#import <Foundation/Foundation.h>

@interface SGDatabaseManager : NSObject

/**
 * Returns the thread-safe shared instance of the database manager.
 */
+ (SGDatabaseManager *)sharedManager;

/** Token & Identity Management */

/**
 * Stores a device token entry with its routing key, E2EE key, and upload status.
 */
- (BOOL)storeDeviceTokenData:(NSData *)routingKey
                     e2eeKey:(NSData *)e2eeKey
                    bundleID:(NSString *)bundleID
                       token:(NSData *)token
                  isUploaded:(BOOL)isUploaded;

/**
 * Returns all token entries that have not yet been uploaded to the server.
 */
- (NSArray *)pendingUploadTokens;

/**
 * Marks a token as successfully uploaded to the server.
 */
- (BOOL)markTokenAsUploaded:(NSData *)routingKey;

/**
 * Resets all tokens to require re-upload on the next connection.
 */
- (void)resetAllTokensToRequireUpload;

/**
 * Returns the token data (E2EE key and bundle ID) for a given routing key.
 */
- (NSDictionary *)tokenDataForRoutingKey:(NSData *)routingKey;

/**
 * Returns all token entries associated with a given bundle identifier.
 */
- (NSArray *)tokenEntriesForBundleIdentifier:(NSString *)bundleID;

/**
 * Removes all token entries for a given bundle identifier.
 */
- (BOOL)removeTokenForBundleIdentifier:(NSString *)bundleID;

/**
 * Returns all active routing keys in the notifications table.
 */
- (NSArray *)allActiveRoutingKeys;

/**
 * Returns the set of distinct bundle identifiers that have registered tokens.
 */
- (NSSet *)registeredBundleIdentifiers;

/** Connectivity & Synchronization */

/**
 * Returns cached DNS resolution data for a domain if it is younger than maxAge seconds.
 */
- (NSDictionary *)cachedDNSForDomain:(NSString *)domain maxAge:(NSTimeInterval)maxAge;

/**
 * Stores a DNS cache entry for a domain with the resolved IP and port.
 */
- (BOOL)storeDNSCacheForDomain:(NSString *)domain ip:(NSString *)ip port:(NSString *)port;

/**
 * Persists a message acknowledgement for later delivery when the connection is restored.
 */
- (BOOL)enqueueAcknowledgementForMessageID:(NSData *)msgID status:(int)status;

/**
 * Returns all pending acknowledgements that have not yet been sent to the server.
 */
- (NSArray *)pendingAcknowledgements;

/**
 * Removes a pending acknowledgement after it has been successfully sent.
 */
- (BOOL)removeAcknowledgementForMessageID:(NSData *)msgID;

/** Daemon Settings */

/**
 * Persists the current keep-alive interval for the given network type.
 */
- (void)saveKeepAliveInterval:(double)interval forWiFi:(BOOL)isWiFi;

/**
 * Loads the persisted keep-alive interval for the given network type.
 */
- (double)loadKeepAliveIntervalForWiFi:(BOOL)isWiFi;

/** Sequence Tracking */

/**
 * Returns the highest device_seq the client has successfully acknowledged.
 * This value is sent in C_POLL so the server only re-delivers unseen messages.
 */
- (int64_t)lastDeliveredSeq;

/**
 * Updates the highest successfully acknowledged device_seq.
 */
- (void)updateLastDeliveredSeq:(int64_t)seq;

/**
 * Closes the underlying SQLite database handle.
 */
- (void)closeDatabase;

/**
 * Runs a passive WAL checkpoint to reclaim space and prevent unbounded WAL growth.
 */
- (void)checkpoint;

@end

#endif