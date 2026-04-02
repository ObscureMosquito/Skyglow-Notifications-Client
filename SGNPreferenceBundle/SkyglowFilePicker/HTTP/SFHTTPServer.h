/*
 * SFHTTPServer.h — minimal, secure file-upload HTTP server.
 * Compile with -fno-objc-arc (MRC).
 *
 * Exposes only GET / (HTML upload form) and POST /upload (multipart file).
 *
 * Security guarantees
 * ───────────────────
 *  • Request headers capped at SFHTTP_HDR_MAX  (8 KB).
 *  • Upload body    capped at SFHTTP_BODY_MAX  (8 MB).
 *  • SO_RCVTIMEO / SO_SNDTIMEO on every connection (15 s).
 *  • Uploaded filename sanitised via lastPathComponent + control-char rejection.
 *  • Final write path verified to remain under the target directory.
 *  • At most SFHTTP_MAX_CONNS (4) concurrent connections accepted.
 *
 * Thread safety: all public methods must be called from the main thread only.
 */

#import <Foundation/Foundation.h>

@class SFHTTPServer;

/* ── Delegate ──────────────────────────────────────────────────────────────── */

@protocol SFHTTPServerDelegate <NSObject>
/** Always called on the main thread. */
- (void)httpServer:(SFHTTPServer *)server didLog:(NSString *)message;
@end

/* ── Server ────────────────────────────────────────────────────────────────── */

@interface SFHTTPServer : NSObject

/**
 * Starts the server, trying ports in [startPort, startPort+9].
 * Sets boundPort and returns YES on success.
 *
 * @param dir   Directory where uploaded files are written.
 * @param port  First port to attempt (e.g. 8080).
 * @param del   Delegate (weak — caller must keep alive for the server's lifetime).
 */
- (BOOL)startInDirectory:(NSString *)dir
               startPort:(uint16_t)port
                delegate:(id<SFHTTPServerDelegate>)del;

/** Stops the server and waits for the accept thread to exit. Safe to call multiple times. */
- (void)stop;

/** Port actually bound.  Valid only after a successful -startInDirectory:startPort:delegate:. */
@property (nonatomic, readonly) uint16_t boundPort;

/** Primary Wi-Fi / Ethernet IPv4 address of this device, or nil if unavailable. */
+ (NSString *)localIPAddress;

@end
