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

#pragma pack(4)
typedef struct {
    uint32_t state;
    uint32_t consecutiveFailures;
    uint32_t currentBackoffSec;
    char     serverIP[16];
    int64_t  daemonStartTime;
    int64_t  lastStateTransitionTime;
    char     errorDetail[128];
    uint32_t activeProfileIndex;
} SGStatusPayload;
#pragma pack()

void SGStatusServer_Start(int64_t startTime);

void SGStatusServer_Post(SGState state, uint32_t failures, uint32_t backoff,
                         const char *ip, const char *errorDetail,
                         uint32_t activeProfile);

void SGStatusServer_Current(SGStatusPayload *outPayload);

const char *SGState_GetName(SGState state);

#ifdef __cplusplus
}
#endif

#endif