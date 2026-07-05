#include "SGKeepAliveStrategy.h"
#include <stdlib.h>

#define SG_KA_MIN_INTERVAL        600.0
#define SG_KA_MAX_INTERVAL_WIFI  3600.0
#define SG_KA_MAX_INTERVAL_WWAN  1680.0
#define SG_KA_INITIAL_INTERVAL    900.0
#define SG_KA_INITIAL_INCREMENT   300.0
#define SG_KA_REFINED_INCREMENT   120.0
#define SG_KA_VARIANCE             20.0
#define SG_KA_BACKOFF_MULTIPLE      0.5
#define SG_KA_HIGH_WATERMARK      330.0
#define SG_KA_STEADY_TIMEOUT_MIN 3600.0

static double sg_growth_step(double increment) {
    double r = (double)arc4random() / 4294967296.0;
    return increment + (2.0 * r - 1.0) * SG_KA_VARIANCE;
}

static void sg_set_interval(SGKeepAliveAlgorithm *a, double v) {
    if (v <= 0.0) v = SG_KA_INITIAL_INTERVAL;
    if (v < a->minInterval) v = a->minInterval;
    if (v > a->maxInterval) v = a->maxInterval;
    if (v != a->currentInterval) {
        a->lastInterval    = a->currentInterval;
        a->currentInterval = v;
    }
}

static void sg_reset(SGKeepAliveAlgorithm *a, double interval) {
    a->stage             = (interval > 0.0) ? SGKeepAliveStageSteadyState
                                            : SGKeepAliveStageInitialGrowth;
    a->highWatermark     = 0.0;
    a->lastGrowthAttempt = 0.0;
    a->lastInterval      = 0.0;
    a->currentInterval   = 0.0;
    sg_set_interval(a, interval);
}

void SGKeepAlive_Initialize(SGKeepAliveAlgorithm *algo, bool isWiFi, double initialInterval) {
    if (!algo) return;
    algo->minInterval = SG_KA_MIN_INTERVAL;
    algo->maxInterval = isWiFi ? SG_KA_MAX_INTERVAL_WIFI : SG_KA_MAX_INTERVAL_WWAN;
    if (initialInterval > 0.0 &&
        (initialInterval < algo->minInterval || initialInterval > algo->maxInterval))
        initialInterval = SG_KA_INITIAL_INTERVAL;
    sg_reset(algo, initialInterval);
}

static void sg_initial_growth(SGKeepAliveAlgorithm *a, SGKeepAliveAction action) {
    if (action == SGKeepAliveActionFailure) {
        sg_set_interval(a, a->lastInterval);
        a->stage = SGKeepAliveStageRefinedGrowth;
        SGKeepAlive_ProcessAction(a, SGKeepAliveActionSuccess);
    } else if (action == SGKeepAliveActionSuccess || action == SGKeepAliveActionProbe) {
        if (a->currentInterval >= a->maxInterval)
            a->stage = SGKeepAliveStageSteadyState;
        if (a->currentInterval > a->highWatermark)
            a->highWatermark = a->currentInterval;
        double next = a->currentInterval + sg_growth_step(SG_KA_INITIAL_INCREMENT);
        a->lastGrowthAttempt = next;
        sg_set_interval(a, next);
    }
}

static void sg_refined_growth(SGKeepAliveAlgorithm *a, SGKeepAliveAction action) {
    if (action == SGKeepAliveActionFailure) {
        sg_set_interval(a, a->lastInterval);
        a->stage = SGKeepAliveStageSteadyState;
        SGKeepAlive_ProcessAction(a, SGKeepAliveActionSuccess);
    } else if (action == SGKeepAliveActionSuccess || action == SGKeepAliveActionProbe) {
        if (a->lastGrowthAttempt > 0.0 && a->currentInterval >= a->lastGrowthAttempt) {
            a->stage = SGKeepAliveStageInitialGrowth;
            SGKeepAlive_ProcessAction(a, SGKeepAliveActionSuccess);
        } else {
            if (a->currentInterval > a->highWatermark)
                a->highWatermark = a->currentInterval;
            sg_set_interval(a, a->currentInterval + sg_growth_step(SG_KA_REFINED_INCREMENT));
        }
    }
}

static void sg_steady_state(SGKeepAliveAlgorithm *a, SGKeepAliveAction action) {
    if (action == SGKeepAliveActionFailure) {
        a->stage = SGKeepAliveStageBackoff;
        SGKeepAlive_ProcessAction(a, SGKeepAliveActionFailure);
        return;
    }
    if (a->highWatermark > 0.0 &&
        a->currentInterval >= a->highWatermark - SG_KA_HIGH_WATERMARK) {
        /* settled */
    } else {
        a->highWatermark = 0.0;
        a->stage = SGKeepAliveStageInitialGrowth;
        SGKeepAlive_ProcessAction(a, SGKeepAliveActionSuccess);
    }
}

static void sg_backoff(SGKeepAliveAlgorithm *a, SGKeepAliveAction action) {
    if (action == SGKeepAliveActionFailure) {
        sg_set_interval(a, a->currentInterval * SG_KA_BACKOFF_MULTIPLE);
    } else if (action == SGKeepAliveActionSuccess || action == SGKeepAliveActionProbe) {
        a->stage = SGKeepAliveStageInitialGrowth;
        SGKeepAlive_ProcessAction(a, SGKeepAliveActionSuccess);
    }
}

void SGKeepAlive_ProcessAction(SGKeepAliveAlgorithm *a, SGKeepAliveAction action) {
    if (!a) return;

    if (action == SGKeepAliveActionReset) {
        sg_reset(a, a->minInterval);
        return;
    }

    if (a->maxInterval - a->minInterval <= SG_KA_REFINED_INCREMENT) {
        a->stage = SGKeepAliveStageSteadyState;
        return;
    }

    switch (a->stage) {
        case SGKeepAliveStageInitialGrowth: sg_initial_growth(a, action); break;
        case SGKeepAliveStageRefinedGrowth: sg_refined_growth(a, action); break;
        case SGKeepAliveStageSteadyState:   sg_steady_state(a, action);   break;
        case SGKeepAliveStageBackoff:       sg_backoff(a, action);        break;
    }
}

void SGKeepAlive_ProcessHeartbeatResult(SGKeepAliveAlgorithm *algo, bool wasSuccessful) {
    SGKeepAlive_ProcessAction(algo,
        wasSuccessful ? SGKeepAliveActionSuccess : SGKeepAliveActionFailure);
}

double SGKeepAlive_GetCurrentInterval(SGKeepAliveAlgorithm *algo) {
    return algo ? algo->currentInterval : SG_KA_INITIAL_INTERVAL;
}

double SGKeepAlive_SteadyStateReprobeDelay(SGKeepAliveAlgorithm *algo) {
    if (!algo || algo->stage != SGKeepAliveStageSteadyState) return 0.0;
    double t = algo->currentInterval * 24.0;
    return (t > SG_KA_STEADY_TIMEOUT_MIN) ? t : SG_KA_STEADY_TIMEOUT_MIN;
}
