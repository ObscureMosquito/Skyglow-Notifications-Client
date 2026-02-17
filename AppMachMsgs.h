#ifndef SKYGLOW_APPMACHMSGS_H
#define SKYGLOW_APPMACHMSGS_H

#include <Foundation/Foundation.h>
#import "TweakMachMessages.h"
#import <mach/mach.h>
#include <bootstrap.h>
#import "Tokens.h"

@interface MachMsgs : NSObject {
    Tokens *tokens;
}

- (void)startMachServer;

@end

#endif /* SKYGLOW_APPMACHMSGS_H */