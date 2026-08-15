#import <Foundation/Foundation.h>
#import "SGControlChannel.h"
#import "SGControlChannelProtocol.h"
#import "SGControlPayloadCodec.h"
#import "SGStatus.h"
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
                NSString *detail = SGCErrorDetailFromResponse(resp);
                if ([detail length]) {
                    fprintf(stderr, "sgnctl: %s: %s\n", ErrName(err),
                            [detail UTF8String]);
                } else {
                    fprintf(stderr, "sgnctl: %s\n", ErrName(err));
                }
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

static int AppCommand(SGControlMessageType type, NSString *bundleID, const char *verb) {
    if (!SG_IsIdentifierStringSafe(bundleID)) { fprintf(stderr, "sgnctl: invalid bundle id\n"); return 2; }
    return Send(type, BundlePayload(bundleID), ^(const SGControlChannelMessage *r) {
        (void)r; printf("%s %s\n", verb, bundleID.UTF8String);
    });
}

#pragma mark - Commands

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

static int CmdDaemon(BOOL enabled) {
    SGCEnabledPayload p; p.enabled = enabled ? 1 : 0;
    return Send(SGCMSG_SET_ENABLED, [NSData dataWithBytes:&p length:sizeof(p)],
        ^(const SGControlChannelMessage *r) { (void)r; printf("daemon %s\n", enabled ? "enabled" : "disabled"); });
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

static int CmdListApps(SGControlMessageType messageType) {
    return Send(messageType, nil, ^(const SGControlChannelMessage *response) {
        NSArray *apps = response
            ? SGCBundleIdListDecode(response->payload, response->payloadLength)
            : nil;
        if (![apps count]) { printf("(none)\n"); return; }
        for (NSString *bundleIdentifier in apps)
            printf("%s\n", [bundleIdentifier UTF8String]);
    });
}

static int CmdProfileList(void) {
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

static int CmdProfileIndex(SGControlMessageType type, int idx, const char *verb) {
    if (idx < 1 || idx > 5) { fprintf(stderr, "sgnctl: profile index must be 1-5\n"); return 2; }
    SGCProfileIndexPayload p; p.profileIndex = (uint8_t)idx;
    return Send(type, [NSData dataWithBytes:&p length:sizeof(p)],
        ^(const SGControlChannelMessage *r) { (void)r; printf("%s profile %d\n", verb, idx); });
}

static int CmdProfileSave(int idx, NSString *address, NSString *pemPath) {
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
        NSString *pemString = [[[NSString alloc]
            initWithData:pem encoding:NSUTF8StringEncoding] autorelease];
        if (!SG_LooksLikePEMCertificate(pemString)) {
            fprintf(stderr, "sgnctl: file does not look like a PEM-encoded server certificate\n");
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

static int CmdProfileIdentity(int idx, NSString *pemPath) {
    if (idx < 1 || idx > 5) { fprintf(stderr, "sgnctl: profile index must be 1-5\n"); return 2; }

    NSData *pem = nil;
    if (pemPath) {
        pem = [NSData dataWithContentsOfFile:pemPath];
        if (!pem) { fprintf(stderr, "sgnctl: cannot read identity file %s\n", pemPath.UTF8String); return 1; }
        if (pem.length > SG_CONTROL_MAX_REG_IDENTITY_PEM_SIZE) {
            fprintf(stderr, "sgnctl: identity file too large (max %d bytes)\n", SG_CONTROL_MAX_REG_IDENTITY_PEM_SIZE);
            return 2;
        }
    }

    SGCRegIdentityPayload p; memset(&p, 0, sizeof(p));
    p.profileIndex = (uint8_t)idx;
    if (pem.length) {
        p.identityPEMLength = (uint16_t)pem.length;
        memcpy(p.identityPEM, pem.bytes, pem.length);
    }
    return Send(SGCMSG_SET_REG_IDENTITY, [NSData dataWithBytes:&p length:sizeof(p)],
        ^(const SGControlChannelMessage *r) {
            (void)r;
            printf("%s registration identity for profile %d\n",
                   pem.length ? "stored" : "removed", idx);
        });
}

static int CmdSetup(int idx, NSString *address, NSString *serverCert, NSString *clientCert) {
    int rc;
    printf("=> saving profile %d...\n", idx);
    rc = CmdProfileSave(idx, address, serverCert);
    if (rc) return rc;

    if (clientCert) {
        printf("=> storing registration identity...\n");
        rc = CmdProfileIdentity(idx, clientCert);
        if (rc) return rc;
    }

    printf("=> activating profile %d...\n", idx);
    rc = CmdProfileIndex(SGCMSG_SET_ACTIVE_PROFILE, idx, "activated");
    if (rc) return rc;

    printf("=> enabling daemon...\n");
    rc = CmdDaemon(YES);
    if (rc) return rc;

    printf("setup complete\n");
    return 0;
}

#pragma mark - Dispatch

static void Usage(void) {
    fprintf(stderr,
        "usage: sgnctl <command> [args...]\n\n"
        "  status                              daemon state + active profile\n"
        "  logs [N]                            last N log lines (default 40)\n\n"
        "  daemon <enable|disable>             toggle the daemon\n"
        "  daemon reload                       reload config from disk\n"
        "  daemon restart                      clean restart via launchd\n\n"
        "  app list                            list Skyglow-registered apps\n"
        "  app register <bundle>               mint a push token\n"
        "  app enable <bundle>                 enable an app\n"
        "  app disable <bundle>                mute an app\n"
        "  app delete <bundle>                 drop an app's registration\n"
        "  app clear-intent <bundle>           clear intent (use native provider)\n"
        "  app test-inject <bundle>            deliver a test notification\n\n"
        "  native list                         list Apple Push registrations\n"
        "  native register <bundle>            request Apple Push registration\n"
        "  native authorize <bundle>           present notification permission prompt\n"
        "  native reset <bundle>               remove Apple token + permission\n\n"
        "  profile list                        list configured profiles\n"
        "  profile save <1-5> <addr> [cert]    create/edit a profile\n"
        "  profile identity <1-5> [pem]        store/remove registration identity\n"
        "  profile activate <1-5>              switch active profile\n"
        "  profile delete <1-5>                delete a profile slot\n\n"
        "  setup <1-5> <addr> <server-cert> [client-cert]\n"
        "      save profile + attach identity + activate + enable\n");
}

static int DispatchDaemon(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: sgnctl daemon <enable|disable|reload|restart>\n"); return 2; }
    NSString *verb = @(argv[2]);
    if ([verb isEqualToString:@"enable"])  return CmdDaemon(YES);
    if ([verb isEqualToString:@"disable"]) return CmdDaemon(NO);
    if ([verb isEqualToString:@"reload"])  return Send(SGCMSG_RELOAD_CONFIG, nil,
        ^(const SGControlChannelMessage *r){ (void)r; printf("reloaded\n"); });
    if ([verb isEqualToString:@"restart"]) return Send(SGCMSG_RESTART_DAEMON, nil,
        ^(const SGControlChannelMessage *r){ (void)r; printf("restart requested\n"); });
    fprintf(stderr, "sgnctl daemon: unknown verb '%s'\n", argv[2]);
    return 2;
}

static int DispatchApp(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: sgnctl app <list|register|enable|disable|delete|clear-intent|test-inject> [bundle]\n"); return 2; }
    NSString *verb = @(argv[2]);
    NSString *bundle = argc > 3 ? @(argv[3]) : nil;

    if ([verb isEqualToString:@"list"])         return CmdListApps(SGCMSG_LIST_SKYGLOW_APPS);

    if (!bundle) { fprintf(stderr, "sgnctl app %s: needs a bundle id\n", argv[2]); return 2; }
    if ([verb isEqualToString:@"register"])     return CmdRegister(bundle);
    if ([verb isEqualToString:@"enable"])       return AppCommand(SGCMSG_ENABLE_APP, bundle, "enabled");
    if ([verb isEqualToString:@"disable"])      return AppCommand(SGCMSG_DISABLE_APP, bundle, "disabled");
    if ([verb isEqualToString:@"delete"])       return AppCommand(SGCMSG_DELETE_APP, bundle, "deleted");
    if ([verb isEqualToString:@"clear-intent"]) return AppCommand(SGCMSG_CLEAR_APP_INTENT, bundle, "cleared");
    if ([verb isEqualToString:@"test-inject"])  return AppCommand(SGCMSG_TEST_INJECT, bundle, "injected");
    fprintf(stderr, "sgnctl app: unknown verb '%s'\n", argv[2]);
    return 2;
}

static int DispatchNative(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: sgnctl native <list|register|authorize|reset> [bundle]\n"); return 2; }
    NSString *verb = @(argv[2]);
    NSString *bundle = argc > 3 ? @(argv[3]) : nil;

    if ([verb isEqualToString:@"list"]) return CmdListApps(SGCMSG_LIST_NATIVE_PUSH_APPS);

    if (!bundle) { fprintf(stderr, "sgnctl native %s: needs a bundle id\n", argv[2]); return 2; }
    if ([verb isEqualToString:@"register"])  return AppCommand(SGCMSG_REGISTER_NATIVE_PUSH_APP, bundle, "native-registered");
    if ([verb isEqualToString:@"authorize"]) return AppCommand(SGCMSG_AUTHORIZE_NATIVE_PUSH_APP, bundle, "authorization-requested");
    if ([verb isEqualToString:@"reset"])     return AppCommand(SGCMSG_RESET_APP_REGISTRATION, bundle, "native-reset");
    fprintf(stderr, "sgnctl native: unknown verb '%s'\n", argv[2]);
    return 2;
}

static int DispatchProfile(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: sgnctl profile <list|save|identity|activate|delete> [args...]\n"); return 2; }
    NSString *verb = @(argv[2]);

    if ([verb isEqualToString:@"list"]) return CmdProfileList();

    if (argc < 4) { fprintf(stderr, "sgnctl profile %s: needs a profile index (1-5)\n", argv[2]); return 2; }
    int idx = atoi(argv[3]);

    if ([verb isEqualToString:@"save"]) {
        if (argc < 5) { fprintf(stderr, "usage: sgnctl profile save <1-5> <address> [server-cert.pem]\n"); return 2; }
        return CmdProfileSave(idx, @(argv[4]), argc > 5 ? @(argv[5]) : nil);
    }
    if ([verb isEqualToString:@"identity"]) return CmdProfileIdentity(idx, argc > 4 ? @(argv[4]) : nil);
    if ([verb isEqualToString:@"activate"]) return CmdProfileIndex(SGCMSG_SET_ACTIVE_PROFILE, idx, "activated");
    if ([verb isEqualToString:@"delete"])   return CmdProfileIndex(SGCMSG_DELETE_PROFILE, idx, "deleted");
    fprintf(stderr, "sgnctl profile: unknown verb '%s'\n", argv[2]);
    return 2;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc < 2) { Usage(); return 2; }
        NSString *cmd = @(argv[1]);

        if ([cmd isEqualToString:@"status"]) return CmdStatus();
        if ([cmd isEqualToString:@"logs"])   return CmdLogs(argc > 2 ? MAX(1, atoi(argv[2])) : 40);

        if ([cmd isEqualToString:@"daemon"])  return DispatchDaemon(argc, argv);
        if ([cmd isEqualToString:@"app"])     return DispatchApp(argc, argv);
        if ([cmd isEqualToString:@"native"])  return DispatchNative(argc, argv);
        if ([cmd isEqualToString:@"profile"]) return DispatchProfile(argc, argv);

        if ([cmd isEqualToString:@"setup"]) {
            if (argc < 5) {
                fprintf(stderr, "usage: sgnctl setup <1-5> <address> <server-cert.pem> [client-cert.pem]\n");
                return 2;
            }
            return CmdSetup(atoi(argv[2]), @(argv[3]), @(argv[4]), argc > 5 ? @(argv[5]) : nil);
        }

        fprintf(stderr, "sgnctl: unknown command '%s'\n", argv[1]);
        Usage();
        return 2;
    }
}
