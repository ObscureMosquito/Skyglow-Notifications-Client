#import <Foundation/Foundation.h>
#import "SGControlChannel.h"
#import "SGControlChannelProtocol.h"
#import "SGStatusServer.h"
#import "SGConfiguration.h"
#import "SGSharedConstants.h"

static const char *StateName(uint32_t s) {
    switch (s) {
        case SGStateStarting: return "Starting";
        case SGStateDisabled: return "Disabled";
        case SGStateIdleUnregistered: return "Idle (unregistered)";
        case SGStateResolvingDNS: return "Resolving DNS";
        case SGStateConnecting: return "Connecting";
        case SGStateAuthenticating: return "Authenticating";
        case SGStateConnected: return "Connected";
        case SGStateBackingOff: return "Backing off";
        case SGStateIdleNoNetwork: return "Idle (no network)";
        case SGStateIdleCircuitOpen: return "Idle (circuit open)";
        case SGStateErrorAuth: return "Error: auth rejected";
        case SGStateErrorBadConfig: return "Error: bad config";
        case SGStateRegistering: return "Registering";
        case SGStateErrorVersionMismatch: return "Error: version mismatch";
        default: return "Unknown";
    }
}

static const char *ErrName(SGControlError e) {
    switch (e) {
        case SGCERR_OK: return "ok";
        case SGCERR_DAEMON_DISABLED: return "daemon is disabled";
        case SGCERR_UNREACHABLE: return "unreachable (is the daemon running?)";
        case SGCERR_TIMEOUT: return "timed out";
        case SGCERR_INVALID_REQUEST: return "invalid request";
        case SGCERR_UNAUTHORIZED: return "unauthorized (run with sudo)";
        case SGCERR_INTERNAL: return "internal daemon error";
        case SGCERR_DAEMON_BUSY: return "daemon busy";
        case SGCERR_NOT_FOUND: return "not found";
        case SGCERR_UNSUPPORTED: return "not supported on this platform";
        default: return "error";
    }
}

static int Send(SGControlMessageType type, NSData *payload,
                void (^onOK)(const SGControlChannelMessage *resp)) {
    SGControlChannel *c = [SGControlChannel clientForServiceName:SKYGLOW_CONTROL_SERVICE_DAEMON];
    if (![c start]) { fprintf(stderr, "sgnctl: cannot open daemon control channel\n"); return 1; }
    __block int rc = 1;
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    [c sendRequest:type payload:payload timeout:10.0
        completion:^(SGControlError err, const SGControlChannelMessage *resp) {
            if (err != SGCERR_OK) {
                fprintf(stderr, "sgnctl: %s\n", ErrName(err));
            } else if (resp && resp->messageType == SGCMSG_ERROR_RESPONSE) {
                fprintf(stderr, "sgnctl: daemon rejected request (%s)\n", ErrName((SGControlError)resp->errorCode));
            } else {
                rc = 0;
                if (onOK) onOK(resp);
            }
            dispatch_semaphore_signal(done);
        }];
    dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(12.0 * NSEC_PER_SEC)));
    return rc;
}

static NSData *BundlePayload(NSString *bundleID) {
    SGCBundleIdPayload p; memset(&p, 0, sizeof(p));
    strlcpy(p.bundleID, bundleID.UTF8String, sizeof(p.bundleID));
    return [NSData dataWithBytes:&p length:sizeof(p)];
}

// A simple app-state command (enable/disable/delete/clear) taking one bundle id.
static int AppCommand(SGControlMessageType type, NSString *bundleID, const char *verb) {
    if (!SG_IsIdentifierStringSafe(bundleID)) { fprintf(stderr, "sgnctl: invalid bundle id\n"); return 2; }
    return Send(type, BundlePayload(bundleID), ^(const SGControlChannelMessage *r) {
        (void)r; printf("%s %s\n", verb, bundleID.UTF8String);
    });
}

static int CmdRegister(NSString *bundleID) {
    if (!SG_IsIdentifierStringSafe(bundleID)) { fprintf(stderr, "sgnctl: invalid bundle id\n"); return 2; }
    SGCTokenRequestPayload req; memset(&req, 0, sizeof(req));
    strlcpy(req.bundleID, bundleID.UTF8String, sizeof(req.bundleID));
    return Send(SGCMSG_TOKEN_REQUEST, [NSData dataWithBytes:&req length:sizeof(req)],
        ^(const SGControlChannelMessage *r) {
            if (r && r->messageType == SGCMSG_TOKEN_RESPONSE &&
                r->payloadLength >= sizeof(SGCTokenResponsePayload)) {
                const SGCTokenResponsePayload *tr = (const SGCTokenResponsePayload *)r->payload;
                uint32_t n = tr->tokenLength > SG_CONTROL_MAX_TOKEN_SIZE ? SG_CONTROL_MAX_TOKEN_SIZE : tr->tokenLength;
                NSMutableString *hex = [NSMutableString string];
                for (uint32_t i = 0; i < n; i++) [hex appendFormat:@"%02x", tr->tokenData[i]];
                printf("registered %s\ntoken: %s\n", bundleID.UTF8String, hex.UTF8String);
            } else {
                printf("registered %s\n", bundleID.UTF8String);
            }
        });
}

static int CmdStatus(void) {
    return Send(SGCMSG_QUERY_STATUS, nil, ^(const SGControlChannelMessage *r) {
        if (!r || r->payloadLength < sizeof(SGStatusPayload)) { printf("(no status)\n"); return; }
        const SGStatusPayload *s = (const SGStatusPayload *)r->payload;
        printf("state           : %s\n", StateName(s->state));
        printf("active profile  : %u\n", s->activeProfileIndex);
        if (s->serverIP[0]) printf("server ip       : %.16s\n", s->serverIP);
        printf("failures        : %u\n", s->consecutiveFailures);
        if (s->state == SGStateBackingOff) printf("backoff         : %us\n", s->currentBackoffSec);
        if (s->errorDetail[0]) printf("last error      : %.128s\n", s->errorDetail);
    });
}

static int CmdDaemon(BOOL enabled) {
    SGCEnabledPayload p; p.enabled = enabled ? 1 : 0;
    return Send(SGCMSG_SET_ENABLED, [NSData dataWithBytes:&p length:sizeof(p)],
        ^(const SGControlChannelMessage *r) { (void)r; printf("daemon %s\n", enabled ? "enabled" : "disabled"); });
}

static int CmdProfileIndex(SGControlMessageType type, int idx, const char *verb) {
    if (idx < 1 || idx > 5) { fprintf(stderr, "sgnctl: profile index must be 1-5\n"); return 2; }
    SGCProfileIndexPayload p; p.profileIndex = (uint8_t)idx;
    return Send(type, [NSData dataWithBytes:&p length:sizeof(p)],
        ^(const SGControlChannelMessage *r) { (void)r; printf("%s profile %d\n", verb, idx); });
}

// Register a server into profile slot idx: address + optional server cert PEM.
// Omitting the PEM (or passing an empty file) edits the address only, keeping
// any existing certificate.
static int CmdSaveProfile(int idx, NSString *address, NSString *pemPath) {
    if (idx < 1 || idx > 5) { fprintf(stderr, "sgnctl: profile index must be 1-5\n"); return 2; }
    if (!SG_IsIdentifierStringSafe(address)) { fprintf(stderr, "sgnctl: invalid server address\n"); return 2; }

    NSData *pem = nil;
    if (pemPath) {
        pem = [NSData dataWithContentsOfFile:pemPath];
        if (!pem) { fprintf(stderr, "sgnctl: cannot read cert file %s\n", pemPath.UTF8String); return 1; }
        if (pem.length > SG_CONTROL_MAX_PROFILE_PEM_SIZE) {
            fprintf(stderr, "sgnctl: cert file too large (max %d bytes)\n", SG_CONTROL_MAX_PROFILE_PEM_SIZE);
            return 2;
        }
    }

    SGCProfileSavePayload p; memset(&p, 0, sizeof(p));
    p.profileIndex = (uint8_t)idx;
    strlcpy(p.serverAddress, address.UTF8String, sizeof(p.serverAddress));
    if (pem.length) {
        p.certificatePEMLength = (uint16_t)pem.length;
        memcpy(p.certificatePEM, pem.bytes, pem.length);
    }
    return Send(SGCMSG_SAVE_PROFILE, [NSData dataWithBytes:&p length:sizeof(p)],
        ^(const SGControlChannelMessage *r) {
            (void)r;
            printf("saved profile %d  server=%s%s\n", idx, address.UTF8String,
                   pem.length ? " (+cert)" : "");
        });
}

static int CmdProfiles(void) {
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:SGPath(SG_PREFS_PLIST_PATH)];
    NSInteger active = [[prefs objectForKey:@"activeProfile"] integerValue];
    BOOL any = NO;
    for (long i = 1; i <= 5; i++) {
        NSString *path = SGPath([NSString stringWithFormat:SG_PROFILE_PLIST_FORMAT, i]);
        NSDictionary *pr = [NSDictionary dictionaryWithContentsOfFile:path];
        if (!pr) continue;
        any = YES;
        NSString *addr = [pr objectForKey:@"server_address"];
        printf("%s profile %ld  server=%s\n", (i == active ? "*" : " "), i,
               addr ? addr.UTF8String : "(none)");
    }
    if (!any) printf("(no profiles configured)\n");
    return 0;
}

static int CmdLogs(int lines) {
    NSString *path = SGPath(SG_LOG_PATH);
    NSString *content = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:NULL];
    if (!content) { fprintf(stderr, "sgnctl: cannot read log at %s\n", path.UTF8String); return 1; }
    NSArray *all = [content componentsSeparatedByString:@"\n"];
    NSUInteger start = all.count > (NSUInteger)lines ? all.count - (NSUInteger)lines : 0;
    for (NSUInteger i = start; i < all.count; i++) {
        NSString *ln = [all objectAtIndex:i];
        if (ln.length) printf("%s\n", ln.UTF8String);
    }
    return 0;
}

static void Usage(void) {
    fprintf(stderr,
        "sgnctl — Skyglow daemon control (run with sudo)\n\n"
        "  status                 daemon connection state + active profile\n"
        "  logs [N]               last N daemon log lines (default 40)\n"
        "  daemon on|off          enable/disable the whole daemon\n"
        "  reload                 reload config from disk\n"
        "  test-inject            inject a test notification\n\n"
        "  register <bundle>      mint a push token for a bundle (prints token)\n"
        "  enable <bundle>        enable an app\n"
        "  disable <bundle>       disable (mute) an app\n"
        "  delete-app <bundle>    drop an app's registration\n"
        "  clear-intent <bundle>  clear app intent (use native provider)\n"
        "  list-apps              list push-registered apps (iOS only)\n\n"
        "  profiles                       list configured profiles + active\n"
        "  save-profile <1-5> <addr> [pem] register a server (address + optional cert PEM)\n"
        "  set-profile <1-5>              switch the active profile\n"
        "  delete-profile <1-5>           delete a profile slot\n");
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc < 2) { Usage(); return 2; }
        NSString *cmd = @(argv[1]);
        NSString *arg = argc > 2 ? @(argv[2]) : nil;
        #define NEED_ARG() do { if (!arg) { fprintf(stderr, "sgnctl: '%s' needs an argument\n", argv[1]); return 2; } } while (0)

        if ([cmd isEqualToString:@"status"])          return CmdStatus();
        if ([cmd isEqualToString:@"logs"])            return CmdLogs(arg ? MAX(1, arg.intValue) : 40);
        if ([cmd isEqualToString:@"reload"])          return Send(SGCMSG_RELOAD_CONFIG, nil, ^(const SGControlChannelMessage *r){ (void)r; printf("reloaded\n"); });
        if ([cmd isEqualToString:@"test-inject"])     return Send(SGCMSG_TEST_INJECT, nil, ^(const SGControlChannelMessage *r){ (void)r; printf("injected\n"); });
        if ([cmd isEqualToString:@"register"])        { NEED_ARG(); return CmdRegister(arg); }
        if ([cmd isEqualToString:@"enable"])          { NEED_ARG(); return AppCommand(SGCMSG_ENABLE_APP, arg, "enabled"); }
        if ([cmd isEqualToString:@"disable"])         { NEED_ARG(); return AppCommand(SGCMSG_DISABLE_APP, arg, "disabled"); }
        if ([cmd isEqualToString:@"delete-app"])      { NEED_ARG(); return AppCommand(SGCMSG_DELETE_APP, arg, "deleted"); }
        if ([cmd isEqualToString:@"clear-intent"])    { NEED_ARG(); return AppCommand(SGCMSG_CLEAR_APP_INTENT, arg, "cleared"); }
        if ([cmd isEqualToString:@"profiles"])        return CmdProfiles();
        if ([cmd isEqualToString:@"save-profile"]) {
            if (argc < 4) { fprintf(stderr, "usage: sgnctl save-profile <1-5> <server-address> [server-cert.pem]\n"); return 2; }
            return CmdSaveProfile(arg.intValue, @(argv[3]), argc > 4 ? @(argv[4]) : nil);
        }
        if ([cmd isEqualToString:@"set-profile"])     { NEED_ARG(); return CmdProfileIndex(SGCMSG_SET_ACTIVE_PROFILE, arg.intValue, "activated"); }
        if ([cmd isEqualToString:@"delete-profile"])  { NEED_ARG(); return CmdProfileIndex(SGCMSG_DELETE_PROFILE, arg.intValue, "deleted"); }
        if ([cmd isEqualToString:@"daemon"]) {
            NEED_ARG();
            if ([arg isEqualToString:@"on"])  return CmdDaemon(YES);
            if ([arg isEqualToString:@"off"]) return CmdDaemon(NO);
            fprintf(stderr, "sgnctl: use 'daemon on' or 'daemon off'\n"); return 2;
        }
        if ([cmd isEqualToString:@"list-apps"]) {
            return Send(SGCMSG_LIST_PUSH_REGISTERED_APPS, nil, ^(const SGControlChannelMessage *r) {
                if (!r || r->payloadLength == 0) { printf("(none)\n"); return; }
                NSUInteger slot = SG_CONTROL_MAX_BUNDLE_ID_SIZE, count = r->payloadLength / slot;
                for (NSUInteger i = 0; i < count; i++) {
                    const char *b = (const char *)(r->payload + i * slot);
                    if (b[0]) printf("%.*s\n", (int)slot, b);
                }
            });
        }

        Usage();
        return 2;
    }
}
