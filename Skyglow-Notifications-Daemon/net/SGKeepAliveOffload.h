#ifndef SGKeepAliveOffload_h
#define SGKeepAliveOffload_h

#include <stdbool.h>

/** Hands the connection keep-alive to Wi-Fi firmware so the CPU can sleep. */

typedef enum {
    SGKAOffloadOK            =  0,
    SGKAOffloadUnimplemented = -1,
    SGKAOffloadNoSocket      = -2,
    SGKAOffloadRejected      = -3,
} SGKAOffloadStatus;

bool SGKAOffload_Available(void);
int  SGKAOffload_TryEnable(double intervalSec);
bool SGKAOffload_IsActive(void);
void SGKAOffload_Reset(void);

#endif
