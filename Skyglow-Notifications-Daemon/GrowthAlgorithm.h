#ifndef SKYGLOW_GROWTH_ALGORITHM_H
#define SKYGLOW_GROWTH_ALGORITHM_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    SGP_STAGE_GROWTH = 0,
    SGP_STAGE_BACKOFF = 1,
    SGP_STAGE_STEADY = 2
} SGPPingStage;

typedef struct {
    SGPPingStage stage;
    double currentInterval;
    double highWatermark;
    bool isWiFi;
} SGPKeepAliveAlgorithm;

/// Initialize the algorithm based on the current network interface
void SGPAlgorithm_Init(SGPKeepAliveAlgorithm *algo, bool isWiFi);

/// Process a ping success (YES) or failure/drop (NO) to adjust the interval
void SGPAlgorithm_ProcessAction(SGPKeepAliveAlgorithm *algo, bool success);

/// Get the current interval to use for the next select() timeout
double SGPAlgorithm_GetInterval(SGPKeepAliveAlgorithm *algo);

#endif /* SKYGLOW_GROWTH_ALGORITHM_H */