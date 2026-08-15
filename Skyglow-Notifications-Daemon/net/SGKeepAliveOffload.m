#import "SGKeepAliveOffload.h"
#import "SGProtocolHandler.h"
#import "SGPlatform.h"
#import "SGLog.h"
#import "SGLogDiagnostics.h"

static bool _active = false;

static int sg_offload_ios6(int fd, double interval) {
    (void)fd; (void)interval;
    return SGKAOffloadUnimplemented;
}

bool SGKAOffload_Available(void) {
    return [[SGPlatform currentPlatform] hasCapability:SGCapabilityKeepAliveOffload];
}

int SGKAOffload_TryEnable(double intervalSec) {
    if (!SGKAOffload_Available()) return SGKAOffloadUnimplemented;
    if (!SGP_IsConnected() || SGP_GetSocketFD() < 0) return SGKAOffloadNoSocket;

    int rc = sg_offload_ios6(SGP_GetSocketFD(), intervalSec);
    _active = (rc == SGKAOffloadOK);
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
