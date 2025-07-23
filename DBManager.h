#import <sqlite3.h>

@interface DBManager : NSObject {
    sqlite3 *database;
}

+ (DBManager *)sharedStorage;
- (BOOL)storeTokenData:(NSData *)routingKey e2eeKey:(NSData *)e2eeKey bundleID:(NSString *)bundleID;
- (NSDictionary *)dataForRoutingKey:(NSData *)routingKey;
- (NSArray *)dataForBundleID:(NSString *)bundleID;

@end