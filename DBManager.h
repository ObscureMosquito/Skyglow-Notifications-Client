#import <sqlite3.h>

@interface DBManager : NSObject {
    sqlite3 *database;
}

+ (DBManager *)sharedStorage;
- (BOOL)storeTokenData:(NSData *)routingKey e2eeKey:(NSData *)e2eeKey bundleID:(NSString *)bundleID token:(NSData *)token;
- (NSDictionary *)dataForRoutingKey:(NSData *)routingKey;
- (NSArray *)dataForBundleID:(NSString *)bundleID;
- (BOOL)removeTokenWithBundleId:(NSString *)bundleID;

@end