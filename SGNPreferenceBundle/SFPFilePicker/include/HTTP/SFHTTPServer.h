/*
 * SFHTTPServer.h
 * Compile with -fno-objc-arc.
 */

#import <Foundation/Foundation.h>

@class SFHTTPServer;

@protocol SFHTTPServerDelegate <NSObject>
- (void)httpServer:(SFHTTPServer *)server didLog:(NSString *)message;

@optional
- (void)httpServer:(SFHTTPServer *)server didUpdateUploadProgress:(float)progress;
@end

@interface SFHTTPServer : NSObject

- (BOOL)startInDirectory:(NSString *)dir
               startPort:(uint16_t)port
                delegate:(id<SFHTTPServerDelegate>)del;

- (void)stop;

@property (nonatomic, readonly) uint16_t boundPort;

+ (NSString *)localIPAddress;

@end