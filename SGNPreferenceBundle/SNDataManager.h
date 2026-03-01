#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#include "../Skyglow-Notifications-Daemon/SGStatusServer.h"

#define SS_SOCKET_PATH "/var/run/skyglow_status.sock"
#define SS_MODE_QUERY  0x51

@interface SNDataManager : NSObject

+ (SNDataManager *)shared;

@property (nonatomic, readonly) NSString *mainPrefsPath;
@property (nonatomic, readonly) NSString *profilePath;
@property (nonatomic, readonly) NSString *dbPath;

/** Main Preferences */
- (NSDictionary *)mainPrefs;
- (BOOL)isEnabled;
- (NSDictionary *)appStatus;
- (void)setAppStatusValue:(BOOL)value forBundleId:(NSString *)bundleId;
- (void)removeAppStatusForBundleId:(NSString *)bundleId;
- (void)setMainPrefValue:(id)value forKey:(NSString *)key;
- (NSString *)serverAddressInput;

/** Profile */
- (NSDictionary *)profile;
- (NSString *)serverAddress;
- (NSString *)deviceAddress;
- (NSString *)serverPubKeyPEM;
- (BOOL)isRegistered;

/** Daemon Status */
- (SGStatusPayload)queryDaemonStatus;
@property (nonatomic, assign) SGStatusPayload latestPayload;
- (void)startWatchingDaemonStatus;
- (void)stopWatchingDaemonStatus;

/** SQLite */
- (NSArray *)allRegisteredTokens;
- (NSSet *)registeredBundleIDs;
- (NSInteger)registeredTokenCount;
- (unsigned long long)dbFileSize;
- (NSDictionary *)cachedDNSForServerAddress:(NSString *)serverAddr;
- (void)clearDNSCache;
- (void)clearAllTokens;
- (void)removeAppFromDatabase:(NSString *)bundleId;

/** Certificate Parsing */
- (NSDictionary *)parseCertificatePEM:(NSString *)pem;

/** Unregistration */
- (void)unregisterDevice;

/** Utilities */
- (NSString *)hexStringFromData:(NSData *)data;
- (NSString *)friendlyStringForState:(SGState)state;
- (UIColor *)colorForState:(SGState)state;

@end