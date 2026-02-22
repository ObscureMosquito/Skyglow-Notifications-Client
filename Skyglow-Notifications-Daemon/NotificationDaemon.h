#ifndef SKYGLOW_NOTIFICATION_DAEMON_H
#define SKYGLOW_NOTIFICATION_DAEMON_H

#import <Foundation/Foundation.h>
#import "Protocol.h"
#import "StatusServer.h"

#define INITIAL_BACKOFF_SEC         2
#define MAX_BACKOFF_SEC             600
#define MAX_CONSECUTIVE_FAILURES    12
#define MAX_JITTER_SEC              5
#define LONG_AUTH_FAIL_BACKOFF_SEC  30
#define CIRCUIT_OPEN_WAIT_SEC       300
#define DNS_RETRY_COUNT             3
#define DNS_RETRY_DELAY_SEC         10
#define kDaemonReloadConfig     "com.skyglow.snd.reload_config"

@interface NotificationDaemon : NSObject <NotificationDelegate>

- (void)connectionLoop;
- (void)networkBecameReachable:(BOOL)isWWAN;
- (void)handleConfigReload;
- (void)requestDisconnect;
- (void)transitionToState:(SGState)newState;
- (void)transitionToState:(SGState)newState
               backoffSec:(uint32_t)backoffSec
                 serverIP:(const char *)serverIP;

@end

#endif /* SKYGLOW_NOTIFICATION_DAEMON_H */