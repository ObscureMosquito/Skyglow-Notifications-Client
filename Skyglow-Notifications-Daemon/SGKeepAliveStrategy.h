#ifndef SGKeepAliveStrategy_h
#define SGKeepAliveStrategy_h

#include <stdbool.h>

typedef enum {
    SGKeepAliveStageGrowth,
    SGKeepAliveStageSteady,
    SGKeepAliveStageBackoff
} SGKeepAliveStage;

typedef struct {
    bool isWiFi;
    SGKeepAliveStage stage;
    double currentInterval;
    double maximumReachedInterval;
} SGKeepAliveAlgorithm;

void SGKeepAlive_Initialize(SGKeepAliveAlgorithm *algo, bool isWiFi, double initialInterval);
void SGKeepAlive_ProcessHeartbeatResult(SGKeepAliveAlgorithm *algo, bool wasSuccessful);
double SGKeepAlive_GetCurrentInterval(SGKeepAliveAlgorithm *algo);

#endif /* SGKeepAliveStrategy_h */