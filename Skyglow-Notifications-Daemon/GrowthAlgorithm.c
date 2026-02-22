#include "GrowthAlgorithm.h"
#include <stdlib.h>

// Constants extracted from Apple's PCMultiStageGrowthAlgorithm
#define SGP_KEEPALIVE_MIN_WWAN 600.0   // 10 minutes
#define SGP_KEEPALIVE_MAX_WWAN 1680.0  // 28 minutes
#define SGP_KEEPALIVE_MIN_WIFI 900.0   // 15 minutes
#define SGP_KEEPALIVE_MAX_WIFI 3600.0  // 1 hour
#define SGP_GROWTH_INCREMENT   180.0   // Add 3 minutes on success
#define SGP_BACKOFF_MULTIPLE   0.75    // Drop by 25% on failure

void SGPAlgorithm_Init(SGPKeepAliveAlgorithm *algo, bool isWiFi) {
    if (!algo) return;
    algo->isWiFi = isWiFi;
    algo->stage = SGP_STAGE_GROWTH;
    algo->currentInterval = isWiFi ? SGP_KEEPALIVE_MIN_WIFI : SGP_KEEPALIVE_MIN_WWAN;
    algo->highWatermark = 0.0;
}

void SGPAlgorithm_ProcessAction(SGPKeepAliveAlgorithm *algo, bool success) {
    if (!algo) return;
    
    double maxInterval = algo->isWiFi ? SGP_KEEPALIVE_MAX_WIFI : SGP_KEEPALIVE_MAX_WWAN;

    if (success) {
        if (algo->stage == SGP_STAGE_GROWTH) {
            if (algo->currentInterval > algo->highWatermark) {
                algo->highWatermark = algo->currentInterval;
            }
            
            // Add jitter [-5s, +5s] exactly like Apple's PCIncrementRandomVariance
            double jitter = ((double)(arc4random_uniform(100)) / 100.0 * 10.0) - 5.0;
            algo->currentInterval += (SGP_GROWTH_INCREMENT + jitter);
            
            if (algo->currentInterval >= maxInterval) {
                algo->currentInterval = maxInterval;
                algo->stage = SGP_STAGE_STEADY;
            }
        }
    } else { 
        // Ping Timeout / Connection Dropped
        if (algo->stage == SGP_STAGE_GROWTH || algo->stage == SGP_STAGE_STEADY) {
            algo->stage = SGP_STAGE_BACKOFF;
            // We pushed the NAT timeout too far. Shrink interval.
            algo->currentInterval = algo->currentInterval * SGP_BACKOFF_MULTIPLE;
        }
    }
}

double SGPAlgorithm_GetInterval(SGPKeepAliveAlgorithm *algo) {
    if (!algo) return 900.0;
    return algo->currentInterval;
}