#import "SGKeepAliveOffload.h"
#import "SGProtocolHandler.h"
#import "SGAvailability.h"
#import "SGLog.h"
#import "SGLogDiagnostics.h"

static bool _active = false;

/*
 * Per-version kernel backends. Each is filled in as its kernel path is RE'd and
 * validated on-device, and returns SGKAOffloadOK only when the firmware actually
 * took the keep-alive. Reached only when SGCapabilityKeepAliveOffload is enabled
 * (off by default), so it stays dormant in release until a version is turned on.
 */
static int sg_offload_ios6(int fd, double interval) {   /* Broadcom keep_alive iovar */
    (void)fd; (void)interval;
    return SGKAOffloadUnimplemented;
}

static int sg_offload_dispatch(int fd, double interval) {
    double v = [[SGAvailability shared] systemVersion];
    if (v >= 6.0 && v < 7.0) return sg_offload_ios6(fd, interval);
    return SGKAOffloadUnimplemented;
}

bool SGKAOffload_Available(void) {
    return [[SGAvailability shared] keepAliveOffloadAvailable];
}

int SGKAOffload_TryEnable(double intervalSec) {
    if (!SGKAOffload_Available()) return SGKAOffloadUnimplemented;
    if (!SGP_IsConnected() || SGP_GetSocketFD() < 0) return SGKAOffloadNoSocket;

    int rc = sg_offload_dispatch(SGP_GetSocketFD(), intervalSec);
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
