#import "SGPlatform.h"

/** the one place a build time platform choice is made. */
id<SGKeyStore>             SGPlatformCreateKeyStore(void);
id<SGNotificationDelivery> SGPlatformCreateDelivery(void);
id<SGNetworkInfo>          SGPlatformCreateNetworkInfo(void);
SGSystemServices          *SGPlatformCreateSystemServices(void);
