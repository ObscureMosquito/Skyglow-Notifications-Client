#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#include "SGStatus.h"

typedef enum {
    SNRegistrationNotRegistered     = 0,
    SNRegistrationRegistered        = 1,
    SNRegistrationNeedsCertificate  = 2
} SNRegistrationStatus;

@interface SNDataManager : NSObject

+ (SNDataManager *)shared;

@property (nonatomic, readonly) NSString *mainPrefsPath;
@property (nonatomic, readonly) NSString *profilePath;
@property (nonatomic, readonly) NSString *dbPath;

- (NSDictionary *)mainPrefs;
- (BOOL)isEnabled;
- (NSDictionary *)appStatus;
- (NSString *)serverAddressInput;
- (NSDictionary *)profile;
- (NSString *)serverAddress;
- (NSString *)deviceAddress;
- (NSString *)serverPubKeyPEM;
- (NSInteger)activeProfileIndex;
- (NSString *)profilePathForIndex:(NSInteger)index;
- (NSDictionary *)profileForIndex:(NSInteger)index;
- (BOOL)profileExistsAtIndex:(NSInteger)index;


- (void)fetchServerCertificateForAddress:(NSString *)serverAddress
                              completion:(void (^)(NSString *pem, NSString *errorMessage))completion;

@property (nonatomic, assign) SGStatusPayload latestPayload;

- (NSArray *)allRegisteredTokens;
- (NSSet *)registeredBundleIDs;
- (NSInteger)registeredTokenCount;
- (unsigned long long)dbFileSize;
- (NSDictionary *)cachedDNSForServerAddress:(NSString *)serverAddr;
- (NSDictionary *)cachedDNSForServerAddress:(NSString *)serverAddr
                               profileIndex:(NSInteger)profileIndex;
- (SNRegistrationStatus)registrationStatusForProfileAtIndex:(NSInteger)profileIndex;
- (NSDictionary *)parseCertificatePEM:(NSString *)pem;
- (NSString *)hexStringFromData:(NSData *)data;
- (NSString *)friendlyStringForState:(SGState)state;
- (UIColor *)colorForState:(SGState)state;
- (NSString *)recoverySuggestionForState:(SGState)state;

@end
