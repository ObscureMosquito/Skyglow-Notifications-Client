#ifndef SKYGLOW_LOCAL_IPC_H
#define SKYGLOW_LOCAL_IPC_H

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <bootstrap.h>

@interface LocalIPC : NSObject
- (void)startMachServer;
@end

kern_return_t LocalIPC_SendPush(NSString *topic, NSDictionary *userInfo);

#endif /* SKYGLOW_LOCAL_IPC_H */