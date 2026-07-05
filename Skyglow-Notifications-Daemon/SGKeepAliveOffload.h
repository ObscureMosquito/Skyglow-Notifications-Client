#ifndef SGKeepAliveOffload_h
#define SGKeepAliveOffload_h

#include <stdbool.h>

/*
 * NIC keep-alive offload: hand the connection's keep-alive to the Wi-Fi
 * firmware so the CPU can stay asleep across the whole interval.
 */

typedef enum {
    SGKAOffloadOK            =  0,   /* firmware accepted the offload  */
    SGKAOffloadUnimplemented = -1,   /* no backend for this device yet */
    SGKAOffloadNoSocket      = -2,   /* not connected                  */
    SGKAOffloadRejected      = -3,   /* OS/firmware refused it         */
} SGKAOffloadStatus;

/* Whether this OS/device is a candidate for offload at all. */
bool SGKAOffload_Available(void);

/* Try to program the firmware keep-alive for the live connection at the given
 * interval. Activates (SGKAOffload_IsActive) only on real success. */
int  SGKAOffload_TryEnable(double intervalSec);

/* YES only while a prior TryEnable actually took; callers suppress their own
 * RTC/interval wakes while this holds. Cleared by SGKAOffload_Reset. */
bool SGKAOffload_IsActive(void);

/* Tear down offload state; call when the connection drops. */
void SGKAOffload_Reset(void);

#endif
