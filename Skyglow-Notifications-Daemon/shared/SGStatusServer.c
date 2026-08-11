#include "SGStatusServer.h"
#include <string.h>
#include <pthread.h>
#include <time.h>

static SGStatusPayload  _current;
static pthread_mutex_t  _lock = PTHREAD_MUTEX_INITIALIZER;

void SGStatusServer_Start(int64_t startTime) {
    pthread_mutex_lock(&_lock);
    memset(&_current, 0, sizeof(_current));
    _current.state                   = SGStateStarting;
    _current.daemonStartTime         = startTime;
    _current.lastStateTransitionTime = startTime;
    pthread_mutex_unlock(&_lock);
}

void SGStatusServer_Post(SGState state, uint32_t failures, uint32_t backoff,
                         const char *ip, const char *errorDetail,
                         uint32_t activeProfile) {
    pthread_mutex_lock(&_lock);
    _current.state                   = state;
    _current.consecutiveFailures     = failures;
    _current.currentBackoffSec       = backoff;
    _current.lastStateTransitionTime = (int64_t)time(NULL);
    if (ip) strlcpy(_current.serverIP, ip, sizeof(_current.serverIP));
    else    _current.serverIP[0] = '\0';
    if (errorDetail) strlcpy(_current.errorDetail, errorDetail, sizeof(_current.errorDetail));
    else             _current.errorDetail[0] = '\0';
    _current.activeProfileIndex      = activeProfile;
    pthread_mutex_unlock(&_lock);
}

void SGStatusServer_Current(SGStatusPayload *outPayload) {
    if (!outPayload) return;
    pthread_mutex_lock(&_lock);
    *outPayload = _current;
    pthread_mutex_unlock(&_lock);
}

const char *SGState_GetName(SGState state) {
    switch (state) {
        case SGStateStarting:            return "Starting";
        case SGStateDisabled:            return "Disabled";
        case SGStateIdleUnregistered:    return "IdleUnregistered";
        case SGStateResolvingDNS:        return "ResolvingDNS";
        case SGStateConnecting:          return "Connecting";
        case SGStateAuthenticating:      return "Authenticating";
        case SGStateConnected:           return "Connected";
        case SGStateBackingOff:          return "BackingOff";
        case SGStateIdleNoNetwork:       return "IdleNoNetwork";
        case SGStateIdleCircuitOpen:     return "IdleCircuitOpen";
        case SGStateErrorAuth:           return "ErrorAuth";
        case SGStateErrorBadConfig:      return "ErrorBadConfig";
        case SGStateRegistering:         return "Registering";
        case SGStateErrorVersionMismatch: return "ErrorVersionMismatch";
        default:                         return "Unknown";
    }
}
