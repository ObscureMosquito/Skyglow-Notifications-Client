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
 * Stores a device token entry with its routing key and E2EE key.
 */
- (BOOL)storeDeviceTokenData:(NSData *)routingKey
                     e2eeKey:(NSData *)e2eeKey
                    bundleID:(NSString *)bundleID
                       token:(NSData *)token;

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
 * Returns the full (routing_key, bundle_id, is_muted) registration set.
 * Each entry is a dictionary with keys: routingKey (NSData), bundleID
 * (NSString), isMuted (NSNumber bool).  Used by SGP_FlushActiveTopicFilter
 * to push the canonical set to the server with per-entry enabled/ignored
 * tagging.
 */
- (NSArray *)allBundleRegistrations;

/**
 * Sets the mute flag for the given bundle.  Muted rows are emitted with
 * C_FILTER's "ignored" tag so the server drops further deliveries; toggling
 * the flag off restores normal routing without losing the token.
 */
- (BOOL)setMuted:(BOOL)muted forBundleIdentifier:(NSString *)bundleID;

/**
 * Returns YES if the row identified by routingKey is muted.  The notification
 * receive path uses this as a defensive drop in case the server is still
 * delivering pushes while a filter resync is in flight.
 */
- (BOOL)isMutedForRoutingKey:(NSData *)routingKey;

/**
 * Returns the set of distinct bundle identifiers that have registered tokens.
 */
- (NSSet *)registeredBundleIdentifiers;

/**
 * Drops every row from the notifications table.  Used when the active
 * profile is deleted — tokens issued by the old server are no longer
 * valid against any future server registration.
 */
- (BOOL)clearAllTokens;

/**
 * Drops every row from the DNS cache.  Used alongside clearAllTokens
 * when an active profile is deleted, so the next connect re-resolves
 * the new server's address from scratch.
 */
- (BOOL)clearAllDNSCache;

/**
 * Drops every server-bound operational row for one profile.  Used when a
 * profile is deleted; other profiles remain untouched.
 */
- (BOOL)clearOperationalStateForProfile:(NSInteger)profileIndex;

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

/** Cross-Session Notification Dedup */

/**
 * Returns YES if the given msg_id was previously delivered (or terminally ACK'd)
 * by this device in any session.  Used to suppress double-delivery when the
 * server retransmits a notification we already handled before a reconnect.
 */
- (BOOL)hasSeenMessageID:(NSData *)msgID;

/**
 * Records that msg_id has been definitively handled (delivered or ACK'd with a
 * terminal failure).  expiresAt is the notification's wire expiry; when zero or
 * already past, the row is retained for at least 24h to absorb late retransmits.
 */
- (void)markMessageIDAsSeen:(NSData *)msgID expiresAt:(int64_t)expiresAt;

/**
 * Deletes seen_messages rows whose expiry has passed.  Safe to call frequently;
 * typically invoked on reconnect to keep the table bounded.
 */
- (void)pruneExpiredSeenMessagesAsOf:(int64_t)nowEpoch;

/** Local-Side Delivery Retry Queue */

/**
 * Persists a notification whose Mach delivery to SpringBoard failed so it can
 * be retried later without lying to the server.  The payload is a binary plist
 * encoding of the parsed notification dictionary.  The row is removed only
 * after either successful redelivery or expiry; the wire ACK is sent at the
 * same moment so the server never sees an ACK for a notification we did not
 * actually surface on the device.
 */
- (BOOL)enqueueLocalPendingDeliveryForMessageID:(NSData *)msgID
                                       bundleID:(NSString *)bundleID
                                        payload:(NSData *)serializedPayload
                                      deviceSeq:(int64_t)deviceSeq
                                      expiresAt:(int64_t)expiresAt;

/**
 * Returns all rows currently queued for local redelivery.  Each entry is a
 * dictionary with keys: msgID (NSData), bundleID (NSString), payload (NSData),
 * deviceSeq (NSNumber, int64), expiresAt (NSNumber, int64).
 */
- (NSArray *)allLocalPendingDeliveries;

/**
 * Removes a local pending delivery row after it has been disposed of.
 */
- (BOOL)removeLocalPendingDeliveryForMessageID:(NSData *)msgID;

/**
 * Removes every local pending delivery row for a given bundle.  Called by
 * the DELETE_APP cascade so queued retries don't loop trying to deliver to
 * an app whose Skyglow registration has just been torn down.
 */
- (BOOL)removeLocalPendingDeliveriesForBundleIdentifier:(NSString *)bundleID;

/**
 * Returns YES if a local-pending row exists for the given msg_id.  Used to
 * silently drop server retransmits we are still trying to redeliver.
 */
- (BOOL)hasLocalPendingDeliveryForMessageID:(NSData *)msgID;

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
