#include <Foundation/Foundation.h>
#import "TweakMachMessages.h"
#import <mach/mach.h>
#include <bootstrap.h>
#import "TweakMachMessages.h"
#import "Tokens.h"
#import <objc/runtime.h>
#import <objc/message.h>

@interface MachMsgs : NSObject {
    Tokens *tokens;
}


- (void)startMachServer;
@end