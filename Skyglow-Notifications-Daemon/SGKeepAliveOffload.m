#import "SGKeepAliveOffload.h"
#import "SGProtocolHandler.h"
#import "SGLog.h"
#import "SGLogDiagnostics.h"
#import <UIKit/UIKit.h>

/*
 * MASTER NIC OFFLOAD SWITCH.
 *   0 = off (default): RTC-wake keep-alive on every version — guaranteed.
 *   1 = on:  attempt a per-version kernel offload. Each version's backend is
 *            best-effort; with no backend, or on failure, _active stays false
 *            and the RTC-wake path continues. Turning it on can never regress
 *            below the RTC baseline.
 */
#define SG_NIC_OFFLOAD_MASTER 0

static bool _active = false;

#if SG_NIC_OFFLOAD_MASTER
/*
 * Per-version kernel backends. Each is filled in as its kernel path is RE'd and
 * validated on-device, and returns SGKAOffloadOK only when the firmware actually
 * took the keep-alive. Wire each into sg_offload_dispatch as it lands.
 */
static int sg_offload_ios6(int fd, double interval) {   /* Broadcom keep_alive iovar */
    (void)fd; (void)interval;
    return SGKAOffloadUnimplemented;
}

static int sg_offload_dispatch(int fd, double interval) {
    double v = [[UIDevice currentDevice] systemVersion].doubleValue;
    if (v >= 6.0 && v < 7.0) return sg_offload_ios6(fd, interval);
    return SGKAOffloadUnimplemented;
}
#endif

bool SGKAOffload_Available(void) {
    return SG_NIC_OFFLOAD_MASTER != 0;
}

int SGKAOffload_TryEnable(double intervalSec) {
#if !SG_NIC_OFFLOAD_MASTER
    (void)intervalSec;
    return SGKAOffloadUnimplemented;
#else
    if (!SGP_IsConnected() || SGP_GetSocketFD() < 0) return SGKAOffloadNoSocket;

    int rc = sg_offload_dispatch(SGP_GetSocketFD(), intervalSec);
    _active = (rc == SGKAOffloadOK);
    SGLOGI(SGKAOffload, "code=%s interval=%.0fs rc=%d result=%s", SGND_KEEPALIVE_OFFLOAD_ATTEMPT,
           intervalSec, rc, _active ? "active" : "inactive");
    if (_active) {
        SGLOGI(SGKAOffload, "code=%s action=cpu_may_sleep", SGND_KEEPALIVE_OFFLOAD_ACTIVE);
    }
    return rc;
#endif
}

bool SGKAOffload_IsActive(void) {
    return _active;
}

void SGKAOffload_Reset(void) {
    _active = false;
}
