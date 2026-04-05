#ifndef SKYGLOW_SG_STATUS_SERVER_H
#define SKYGLOW_SG_STATUS_SERVER_H

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/** SGState Enum */
typedef enum : uint32_t {
    SGStateStarting            = 0,
    SGStateDisabled            = 1,
    SGStateIdleUnregistered    = 2,
    SGStateResolvingDNS        = 3,
    SGStateIdleDNSFailed       = 4,
    SGStateConnecting          = 5,
    SGStateAuthenticating      = 6,
    SGStateConnected           = 7,
    SGStateBackingOff          = 8,
    SGStateIdleNoNetwork       = 9,
    SGStateIdleCircuitOpen     = 10,
    SGStateErrorAuth           = 11,
    SGStateErrorBadConfig      = 12,
    SGStateError               = 13,
    SGStateShuttingDown        = 14,
    SGStateRegistering         = 15
} SGState;

/**
 * Fixed-size binary packet for IPC status communication.
 *
 * IMPORTANT: Both the daemon and the preference bundle read/write this struct
 * across a Unix socket.  They ship in the same .deb so the sizes always match.
 * If you change this struct, rebuild BOTH targets.
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
 * Starts the status server on a background thread using the given socket path.
 */
void SGStatusServer_Start(const char *socketPath, int64_t startTime);

/**
 * Updates the global state and broadcasts to all active watchers.
 * @param errorDetail  Human-readable error string (may be NULL or "").
 * @param activeProfile  1-based index of the active profile (0 = none).
 */
void SGStatusServer_Post(SGState state, uint32_t failures, uint32_t backoff,
                         const char *ip, const char *errorDetail,
                         uint32_t activeProfile);

/**
 * Fills outPayload with the current daemon status snapshot.
 */
void SGStatusServer_Current(SGStatusPayload *outPayload);

/**
 * Gracefully shuts down the status server.
 */
void SGStatusServer_Shutdown(void);

/**
 * Returns a human-readable string for the given state.
 */
const char *SGState_GetName(SGState state);

#ifdef __cplusplus
}
#endif

#endif