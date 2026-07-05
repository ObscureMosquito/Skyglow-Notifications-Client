#import "SGKeepAliveOffload.h"
#import "SGProtocolHandler.h"
#import "SGAvailability.h"
#import "SGLog.h"
#import "SGLogDiagnostics.h"

/* Force the capability on so the path is exercisable before a real per-device
 * version gate exists in kCapabilityTable. Drop this once that gate lands. */
#define SG_KEEPALIVE_OFFLOAD_PLACEHOLDER 1

static bool _active = false;

bool SGKAOffload_Available(void) {
#if SG_KEEPALIVE_OFFLOAD_PLACEHOLDER
    return true;
#else
    return [[SGAvailability shared] isCapabilityAvailable:SGCapabilityKeepAliveOffload];
#endif
}

int SGKAOffload_TryEnable(double intervalSec) {
    if (!SGKAOffload_Available()) {
        SGLOGD(SGKAOffload, "code=%s result=unavailable", SGND_KEEPALIVE_OFFLOAD_UNAVAILABLE);
        return SGKAOffloadUnimplemented;
    }
    if (!SGP_IsConnected() || SGP_GetSocketFD() < 0) {
        return SGKAOffloadNoSocket;
    }

    /* Per-device kernel programming lands here: craft the firmware keep-alive
     * frame and hand it to the Wi-Fi driver, then set _active = true on success.
     * Until a backend exists this returns Unimplemented and _active stays false,
     * so the RTC-wake path is never suppressed. */
    int rc = SGKAOffloadUnimplemented;

    SGLOGI(SGKAOffload, "code=%s interval=%.0fs rc=%d result=%s", SGND_KEEPALIVE_OFFLOAD_ATTEMPT,
           intervalSec, rc, _active ? "active" : "inactive");
    if (_active) {
        SGLOGI(SGKAOffload, "code=%s action=cpu_may_sleep", SGND_KEEPALIVE_OFFLOAD_ACTIVE);
    }
    return rc;
}

bool SGKAOffload_IsActive(void) {
    return _active;
}

void SGKAOffload_Reset(void) {
    _active = false;
}
