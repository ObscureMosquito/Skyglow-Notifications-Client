#include "DBManager.h"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <CommonCrypto/CommonDigest.h>
#include "Protocol.h"
#import "CryptoManager.h"
#import "DBManager.h"
#import "TweakMachMessages.h"



@interface Tokens :  NSObject {
    dispatch_semaphore_t _tokenRegistrationSemaphore;
    BOOL _tokenRegistrationCompleted;
    NSString *_pendingBundleID;
}

- (NSData*)generateDeviceToken:(NSString*)bundleID error:(NSError*)err;
@end