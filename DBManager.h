#ifndef SKYGLOW_DBMANAGER_H
#define SKYGLOW_DBMANAGER_H

#import <Foundation/Foundation.h>
#import <sqlite3.h>

@interface DBManager : NSObject {
    sqlite3 *database;
}

+ (DBManager *)sharedStorage;

- (BOOL)storeTokenData:(NSData *)routingKey
               e2eeKey:(NSData *)e2eeKey
              bundleID:(NSString *)bundleID
                 token:(NSData *)token;

- (NSDictionary *)dataForRoutingKey:(NSData *)routingKey;
- (NSArray *)dataForBundleID:(NSString *)bundleID;
- (BOOL)removeTokenWithBundleId:(NSString *)bundleID;

// DNS cache
- (NSDictionary *)cachedDNSForDomain:(NSString *)domain maxAgeSeconds:(NSTimeInterval)maxAge;
- (BOOL)storeDNSCache:(NSString *)domain ip:(NSString *)ip port:(NSString *)port;

@end

#endif /* SKYGLOW_DBMANAGER_H */