#ifndef SGKeepAliveStrategy_h
#define SGKeepAliveStrategy_h

#include <stdbool.h>

/**
 * Stages of the adaptive keep-alive algorithm.
 */
typedef enum {
    SGKeepAliveStageGrowth,
    SGKeepAliveStageSteady,
    SGKeepAliveStageBackoff
} SGKeepAliveStage;

/**
 * State for the adaptive keep-alive interval algorithm.
 */
typedef struct {
    bool isWiFi;
    SGKeepAliveStage stage;
    double currentInterval;
    double maximumReachedInterval;
} SGKeepAliveAlgorithm;

/**
 * Initializes or resets the keep-alive algorithm for the given network type.
 */
void SGKeepAlive_Initialize(SGKeepAliveAlgorithm *algo, bool isWiFi, double initialInterval);

/**
 * Adjusts the keep-alive interval based on whether the last heartbeat succeeded.
 */
void SGKeepAlive_ProcessHeartbeatResult(SGKeepAliveAlgorithm *algo, bool wasSuccessful);

/**
 * Returns the current keep-alive interval in seconds.
 */
double SGKeepAlive_GetCurrentInterval(SGKeepAliveAlgorithm *algo);

#endif