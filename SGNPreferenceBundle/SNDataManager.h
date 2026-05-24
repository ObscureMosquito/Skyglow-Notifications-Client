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

/** Profile — active profile shortcuts (delegates to active profile index) */
- (NSDictionary *)profile;
- (NSString *)serverAddress;
- (NSString *)deviceAddress;
- (NSString *)serverPubKeyPEM;
- (BOOL)isRegistered;

/** Multi-Profile API */
- (NSInteger)activeProfileIndex;
- (void)setActiveProfileIndex:(NSInteger)index;
- (NSString *)profilePathForIndex:(NSInteger)index;
- (NSDictionary *)profileForIndex:(NSInteger)index;
- (BOOL)profileExistsAtIndex:(NSInteger)index;
- (BOOL)deleteProfileAtIndex:(NSInteger)index;
- (BOOL)importProfileFromPEMAtPath:(NSString *)path serverAddress:(NSString *)serverAddress profileIndex:(NSInteger)index;
- (BOOL)importProfileFromPEMAtPath:(NSString *)path serverAddress:(NSString *)serverAddress;

/** Auto-fetch — resolve _sgn.<addr> TXT for http_addr, then GET <http_addr>/snd/server_cert.pem.
 *  Completion fires on the main queue with either a PEM string or a human-readable error. */
- (void)fetchServerCertificateForAddress:(NSString *)serverAddress
                              completion:(void (^)(NSString *pem, NSString *errorMessage))completion;

/** Persists a PEM obtained via fetchServerCertificateForAddress: and writes the profile plist. */
- (BOOL)installFetchedCertificatePEM:(NSString *)pem
                       serverAddress:(NSString *)serverAddress
                        profileIndex:(NSInteger)index;

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
- (void)unregisterProfileAtIndex:(NSInteger)index;

/** Utilities */
- (NSString *)hexStringFromData:(NSData *)data;
- (NSString *)friendlyStringForState:(SGState)state;
- (UIColor *)colorForState:(SGState)state;
- (NSString *)recoverySuggestionForState:(SGState)state;

@end