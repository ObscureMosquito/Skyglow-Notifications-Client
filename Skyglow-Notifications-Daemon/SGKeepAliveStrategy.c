#include "SGKeepAliveStrategy.h"
#include <stdlib.h>

#define MIN_WWAN 600.0
#define MAX_WWAN 1680.0
#define MIN_WIFI 900.0
#define MAX_WIFI 3600.0
#define INCREMENT 180.0
#define BACKOFF   0.75

void SGKeepAlive_Initialize(SGKeepAliveAlgorithm *algo, bool isWiFi, double initialInterval) {
    if (!algo) return;
    algo->isWiFi = isWiFi;
    algo->stage = SGKeepAliveStageGrowth;
    
    double minLimit = isWiFi ? MIN_WIFI : MIN_WWAN;
    double maxLimit = isWiFi ? MAX_WIFI : MAX_WWAN;
    
    if (initialInterval >= minLimit && initialInterval <= maxLimit) {
        algo->currentInterval = initialInterval;
    } else {
        algo->currentInterval = minLimit;
    }
    
    algo->maximumReachedInterval = 0.0;
    algo->consecutiveSuccesses = 0;
}

void SGKeepAlive_ProcessHeartbeatResult(SGKeepAliveAlgorithm *algo, bool wasSuccessful) {
    if (!algo) return;
    double maxLimit = algo->isWiFi ? MAX_WIFI : MAX_WWAN;

    if (wasSuccessful) {
        if (algo->stage == SGKeepAliveStageBackoff) {
            algo->consecutiveSuccesses++;
            if (algo->consecutiveSuccesses >= 3) {
                algo->stage = SGKeepAliveStageGrowth;
                algo->consecutiveSuccesses = 0;
            }
        } else {
            algo->consecutiveSuccesses++;
        }

        if (algo->stage == SGKeepAliveStageGrowth) {
            double jitter = ((double)(arc4random_uniform(100)) / 100.0 * 10.0) - 5.0;
            algo->currentInterval += (INCREMENT + jitter);
            if (algo->currentInterval >= maxLimit) {
                algo->currentInterval = maxLimit;
                algo->stage = SGKeepAliveStageSteady;
            }
        }
    } else {
        algo->consecutiveSuccesses = 0;
        if (algo->stage != SGKeepAliveStageBackoff) {
            algo->stage = SGKeepAliveStageBackoff;
            algo->currentInterval *= BACKOFF;
        }
    }
}

double SGKeepAlive_GetCurrentInterval(SGKeepAliveAlgorithm *algo) {
    return algo ? algo->currentInterval : 900.0;
}