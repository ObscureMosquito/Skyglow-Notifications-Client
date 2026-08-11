#ifndef SGKeepAliveStrategy_h
#define SGKeepAliveStrategy_h

#include <stdbool.h>

/*
 * Growth stages:
 *   InitialGrowth — climb aggressively (+300s steps)
 *   RefinedGrowth — after a failure, creep back up carefully (+120s steps)
 *   SteadyState   — settled at a sustainable interval; occasionally re-probe
 *   Backoff       — halve the interval until the network recovers
 */
typedef enum {
    SGKeepAliveStageInitialGrowth = 0,
    SGKeepAliveStageRefinedGrowth = 1,
    SGKeepAliveStageSteadyState   = 2,
    SGKeepAliveStageBackoff       = 3,
} SGKeepAliveStage;

/*
 * Actions given to the algorithm:
 *   Success — a keepalive was acknowledged (pong received)
 *   Failure — a keepalive timed out
 *   Probe   — the SteadyState re-probe timer fired
 *   Reset   — hard reset to the minimum interval
 */
typedef enum {
    SGKeepAliveActionSuccess = 0,
    SGKeepAliveActionFailure = 1,
    SGKeepAliveActionProbe   = 2,
    SGKeepAliveActionReset   = 3,
} SGKeepAliveAction;

typedef struct {
    double           minInterval;
    double           maxInterval;
    double           currentInterval;
    double           lastInterval;
    double           highWatermark;
    double           lastGrowthAttempt;
    SGKeepAliveStage stage;
} SGKeepAliveAlgorithm;

/** Initializes/resets the algorithm for the given network type */
void SGKeepAlive_Initialize(SGKeepAliveAlgorithm *algo, bool isWiFi, double initialInterval);

/** Feeds Success or Failure. */
void SGKeepAlive_ProcessHeartbeatResult(SGKeepAliveAlgorithm *algo, bool wasSuccessful);

/** Drives the state machine with one action. */
void SGKeepAlive_ProcessAction(SGKeepAliveAlgorithm *algo, SGKeepAliveAction action);

/** Current keep-alive interval in seconds. */
double SGKeepAlive_GetCurrentInterval(SGKeepAliveAlgorithm *algo);

/** Delay before the next SteadyState reprobe */
double SGKeepAlive_SteadyStateReprobeDelay(SGKeepAliveAlgorithm *algo);

#endif
