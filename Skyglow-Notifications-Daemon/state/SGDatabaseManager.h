#ifndef SKYGLOW_SG_DATABASE_MANAGER_H
#define SKYGLOW_SG_DATABASE_MANAGER_H

#import <Foundation/Foundation.h>

@interface SGDatabaseManager : NSObject

/** Returns the thread-safe shared instance of the database manager duh*/
+ (SGDatabaseManager *)sharedManager;

/** Stores a device token entry with its routing key and E2EE key */
- (BOOL)storeDeviceTokenData:(NSData *)routingKey
                     e2eeKey:(NSData *)e2eeKey
                    bundleID:(NSString *)bundleID
                       token:(NSData *)token;

/** Returns the token data (E2EE key and bundle ID) for a given routing key */
- (NSDictionary *)tokenDataForRoutingKey:(NSData *)routingKey;
- (NSArray *)tokenEntriesForBundleIdentifier:(NSString *)bundleID;
- (BOOL)removeTokenForBundleIdentifier:(NSString *)bundleID;
- (BOOL)removeAllStateForBundleIdentifier:(NSString *)bundleID;
- (NSArray *)allBundleRegistrations;

/** Sets the mute flag for the given bundle */
- (BOOL)setMuted:(BOOL)muted forBundleIdentifier:(NSString *)bundleID;
- (BOOL)isMutedForRoutingKey:(NSData *)routingKey;
- (NSSet *)registeredBundleIdentifiers;
- (BOOL)clearAllTokens;
- (BOOL)clearAllDNSCache;

/** Drops every server-bound operational row for one profile */
- (BOOL)clearOperationalStateForProfile:(NSInteger)profileIndex;

/** Returns cached DNS resolution data for a domain if it is younger than maxAge seconds */
- (NSDictionary *)cachedDNSForDomain:(NSString *)domain maxAge:(NSTimeInterval)maxAge;
- (BOOL)storeDNSCacheForDomain:(NSString *)domain ip:(NSString *)ip port:(NSString *)port;
- (BOOL)enqueueAcknowledgementForMessageID:(NSData *)msgID status:(int)status;

/** Returns all pending acknowledgements that have not yet been sent to the server */
- (NSArray *)pendingAcknowledgements;
- (BOOL)removeAcknowledgementForMessageID:(NSData *)msgID;
- (void)saveKeepAliveInterval:(double)interval forWiFi:(BOOL)isWiFi;
- (double)loadKeepAliveIntervalForWiFi:(BOOL)isWiFi;

/** Returns the highest device_seq the client has successfully acknowledged */
- (int64_t)lastDeliveredSeq;

/** Updates the highest successfully acknowledged device_seq */
- (void)updateLastDeliveredSeq:(int64_t)seq;
- (BOOL)hasSeenMessageID:(NSData *)msgID;
- (void)markMessageIDAsSeen:(NSData *)msgID expiresAt:(int64_t)expiresAt;
- (void)pruneExpiredSeenMessagesAsOf:(int64_t)nowEpoch;

/** Local-Side Delivery Retry Queue */

/** Persists a notification whose Mach delivery to its manager failed */
- (BOOL)enqueueLocalPendingDeliveryForMessageID:(NSData *)msgID
                                       bundleID:(NSString *)bundleID
                                        payload:(NSData *)serializedPayload
                                      deviceSeq:(int64_t)deviceSeq
                                      expiresAt:(int64_t)expiresAt;

/** Returns all rows currently queued for local redelivery. */
- (NSArray *)allLocalPendingDeliveries;
- (BOOL)removeLocalPendingDeliveryForMessageID:(NSData *)msgID;
- (BOOL)removeLocalPendingDeliveriesForBundleIdentifier:(NSString *)bundleID;
- (BOOL)hasLocalPendingDeliveryForMessageID:(NSData *)msgID;
- (void)closeDatabase;

/** Runs a passive WAL checkpoint to reclaim space and prevent unbounded WAL growth */
- (void)checkpoint;

@end

#endif
