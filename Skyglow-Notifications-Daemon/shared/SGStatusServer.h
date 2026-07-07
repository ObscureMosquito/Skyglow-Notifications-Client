#ifndef SKYGLOW_SG_STATUS_SERVER_H
#define SKYGLOW_SG_STATUS_SERVER_H

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum : uint32_t {
    SGStateStarting             = 0,
    SGStateDisabled             = 1,
    SGStateIdleUnregistered     = 2,
    SGStateResolvingDNS         = 3,
    SGStateConnecting           = 4,
    SGStateAuthenticating       = 5,
    SGStateConnected            = 6,
    SGStateBackingOff           = 7,
    SGStateIdleNoNetwork        = 8,
    SGStateIdleCircuitOpen      = 9,
    SGStateErrorAuth            = 10,
    SGStateErrorBadConfig       = 11,
    SGStateRegistering          = 12,
    SGStateErrorVersionMismatch = 13
} SGState;

/**
 * Fixed-size binary status snapshot.
 *
 * The daemon serialises this struct verbatim over the control channel (Mach):
 * SGCMSG_QUERY_STATUS replies and SGCEVT_STATE_CHANGED events carry its raw
 * bytes, which the preference bundle reads back.  (There is no Unix socket —
 * that transport was removed; see SGStatusServer.c.)  #pragma pack(4) fixes the
 * layout so it is identical under 32-bit (armv7) and 64-bit (arm64); daemon and
 * Settings share an arch per device.  They ship in the same .deb, so sizes
 * always match — if you change this struct, rebuild BOTH targets.
 */
#pragma pack(4)
typedef struct {
    uint32_t state;
    uint32_t consecutiveFailures;
    uint32_t currentBackoffSec;
    char     serverIP[16];
    int64_t  daemonStartTime;
    int64_t  lastStateTransitionTime;
    char     errorDetail[128];      /* Human-readable error, null-terminated  */
    uint32_t activeProfileIndex;    /* 1-5, or 0 if no profile is active     */
} SGStatusPayload;
#pragma pack()

/**
 * Initializes the in-process status cache with the daemon start time.
 * Subsequent SGStatusServer_Post calls overwrite the cached snapshot;
 * SGStatusServer_Current reads it.  Status reaches external consumers
 * via the control channel (SGCMSG_QUERY_STATUS for snapshots,
 * SGCEVT_STATE_CHANGED for live events) — this module owns no transport.
 */
void SGStatusServer_Start(int64_t startTime);

/** Atomically updates every field of the cached snapshot. */
void SGStatusServer_Post(SGState state, uint32_t failures, uint32_t backoff,
                         const char *ip, const char *errorDetail,
                         uint32_t activeProfile);

/** Atomically copies the cached snapshot into outPayload. */
void SGStatusServer_Current(SGStatusPayload *outPayload);

/**
 * Returns a human-readable string for the given state.
 */
const char *SGState_GetName(SGState state);

#ifdef __cplusplus
}
#endif

#endif