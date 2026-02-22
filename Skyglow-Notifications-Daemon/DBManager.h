#ifndef SKYGLOW_DBMANAGER_H
#define SKYGLOW_DBMANAGER_H

#import <Foundation/Foundation.h>
#import <sqlite3.h>

@interface DBManager : NSObject {
    sqlite3 *database;
    dispatch_queue_t _dbQueue;
}

+ (DBManager *)sharedStorage;

- (BOOL)storeTokenData:(NSData *)routingKey
               e2eeKey:(NSData *)e2eeKey
              bundleID:(NSString *)bundleID
                 token:(NSData *)token
            isUploaded:(BOOL)isUploaded;
- (NSArray *)pendingUploadTokens;
- (BOOL)markTokenUploaded:(NSData *)routingKey;
- (void)resetAllTokensNeedUpload;
- (NSDictionary *)dataForRoutingKey:(NSData *)routingKey;
- (NSArray *)dataForBundleID:(NSString *)bundleID;
- (BOOL)removeTokenWithBundleId:(NSString *)bundleID;
- (NSDictionary *)cachedDNSForDomain:(NSString *)domain maxAgeSeconds:(NSTimeInterval)maxAge;
- (BOOL)storeDNSCache:(NSString *)domain ip:(NSString *)ip port:(NSString *)port;
- (BOOL)queueAckForMsgID:(NSData *)msgID status:(int)status;
- (NSArray *)pendingAcks;
- (BOOL)removeAckForMsgID:(NSData *)msgID;
- (NSArray *)allActiveRoutingKeys;

@end

#endif /* SKYGLOW_DBMANAGER_H */