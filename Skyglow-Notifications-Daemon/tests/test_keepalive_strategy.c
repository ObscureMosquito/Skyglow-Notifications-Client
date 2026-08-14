#include <stdio.h>
#include "sg_test.h"
#include "SGKeepAliveStrategy.h"

#define MIN        600.0
#define MAX_WIFI  3600.0
#define MAX_WWAN  1680.0
#define INITIAL    900.0
#define GROW       300.0
#define REFINE     120.0
#define VAR         20.0
#define GROW_LO   (GROW - VAR)
#define GROW_HI   (GROW + VAR)
#define REFINE_LO (REFINE - VAR)
#define REFINE_HI (REFINE + VAR)


// feed n successes, returning the interval after each is optional
static void feed(SGKeepAliveAlgorithm *a, SGKeepAliveAction act, int n) {
    for (int i = 0; i < n; i++) SGKeepAlive_ProcessAction(a, act);
}

static void test_init_bounds_and_warm_start(void) {
    SGKeepAliveAlgorithm a;

    SGKeepAlive_Initialize(&a, true, INITIAL);
    CHECK(a.minInterval == MIN, "wifi min %f", a.minInterval);
    CHECK(a.maxInterval == MAX_WIFI, "wifi max %f", a.maxInterval);
    CHECK(a.currentInterval == INITIAL, "wifi start %f", a.currentInterval);
    CHECK(a.stage == SGKeepAliveStageSteadyState, "warm start not steady: %d", a.stage);

    SGKeepAlive_Initialize(&a, false, INITIAL);
    CHECK(a.maxInterval == MAX_WWAN, "wwan max %f", a.maxInterval);

    SGKeepAlive_Initialize(&a, true, 99999.0);
    CHECK(a.currentInterval == INITIAL, "oob start %f", a.currentInterval);
    CHECK(a.stage == SGKeepAliveStageSteadyState, "oob not steady");

    SGKeepAlive_Initialize(&a, true, 0.0);
    CHECK(a.stage == SGKeepAliveStageInitialGrowth, "cold not initial-growth: %d", a.stage);
    CHECK(a.currentInterval == INITIAL, "cold start %f", a.currentInterval);
}

static void test_growth_step_and_cap(void) {
    SGKeepAliveAlgorithm a;
    SGKeepAlive_Initialize(&a, true, 0.0);

    double before = a.currentInterval;
    SGKeepAlive_ProcessAction(&a, SGKeepAliveActionSuccess);
    double step = a.currentInterval - before;
    CHECK(step >= GROW_LO && step <= GROW_HI, "initial step %f not in [%f,%f]", step, GROW_LO, GROW_HI);

    feed(&a, SGKeepAliveActionSuccess, 40);
    CHECK(a.currentInterval == MAX_WIFI, "not capped at wifi max: %f", a.currentInterval);
    CHECK(a.stage == SGKeepAliveStageSteadyState, "not steady at cap: %d", a.stage);

    SGKeepAlive_ProcessAction(&a, SGKeepAliveActionSuccess);
    CHECK(a.currentInterval == MAX_WIFI, "grew past cap: %f", a.currentInterval);
}

static void test_wwan_cap(void) {
    SGKeepAliveAlgorithm a;
    SGKeepAlive_Initialize(&a, false, 0.0);
    feed(&a, SGKeepAliveActionSuccess, 40);
    CHECK(a.currentInterval == MAX_WWAN, "wwan not capped at 1680: %f", a.currentInterval);
}

static void test_steady_failure_backs_off_by_half(void) {
    SGKeepAliveAlgorithm a;
    SGKeepAlive_Initialize(&a, true, 0.0);
    feed(&a, SGKeepAliveActionSuccess, 40); //settle at 3600 steady
    CHECK(a.currentInterval == MAX_WIFI, "precondition: %f", a.currentInterval);

    SGKeepAlive_ProcessAction(&a, SGKeepAliveActionFailure); //steady -> backoff -> halve
    CHECK(a.currentInterval == MAX_WIFI * 0.5, "one failure should halve: %f", a.currentInterval);
    CHECK(a.stage == SGKeepAliveStageBackoff, "not in backoff: %d", a.stage);

    SGKeepAlive_ProcessAction(&a, SGKeepAliveActionFailure); //halve agaun
    CHECK(a.currentInterval == MAX_WIFI * 0.25, "second failure halve: %f", a.currentInterval);
}

static void test_backoff_clamps_to_min(void) {
    SGKeepAliveAlgorithm a;
    SGKeepAlive_Initialize(&a, true, 0.0);
    feed(&a, SGKeepAliveActionSuccess, 40);
    feed(&a, SGKeepAliveActionFailure, 20);
    CHECK(a.currentInterval == MIN, "backoff below min: %f", a.currentInterval);
}

static void test_backoff_recovers_to_growth(void) {
    SGKeepAliveAlgorithm a;
    SGKeepAlive_Initialize(&a, true, 0.0);
    feed(&a, SGKeepAliveActionSuccess, 40);
    SGKeepAlive_ProcessAction(&a, SGKeepAliveActionFailure);
    double atBackoff = a.currentInterval;

    SGKeepAlive_ProcessAction(&a, SGKeepAliveActionSuccess);
    CHECK(a.stage == SGKeepAliveStageInitialGrowth, "backoff success not -> growth: %d", a.stage);
    double step = a.currentInterval - atBackoff;
    CHECK(step >= GROW_LO && step <= GROW_HI, "recovery step %f", step);
}

static void test_initial_failure_enters_refined_growth(void) {
    SGKeepAliveAlgorithm a;
    SGKeepAlive_Initialize(&a, true, 0.0);
    SGKeepAlive_ProcessAction(&a, SGKeepAliveActionSuccess);
    CHECK(a.stage == SGKeepAliveStageInitialGrowth, "precondition stage: %d", a.stage);
    double lastGood = a.lastInterval;

    SGKeepAlive_ProcessAction(&a, SGKeepAliveActionFailure);
    CHECK(a.stage == SGKeepAliveStageRefinedGrowth, "not refined after initial fail: %d", a.stage);
    double delta = a.currentInterval - lastGood;
    CHECK(delta >= REFINE_LO && delta <= REFINE_HI, "refined step %f not in [%f,%f]", delta, REFINE_LO, REFINE_HI);
}

static void test_refined_growth_climbs_by_120(void) {
    SGKeepAliveAlgorithm a;
    SGKeepAlive_Initialize(&a, true, 0.0);
    SGKeepAlive_ProcessAction(&a, SGKeepAliveActionSuccess);
    SGKeepAlive_ProcessAction(&a, SGKeepAliveActionFailure);
    CHECK(a.stage == SGKeepAliveStageRefinedGrowth, "precondition: %d", a.stage);

    double before = a.currentInterval;
    SGKeepAlive_ProcessAction(&a, SGKeepAliveActionSuccess);
    double delta = a.currentInterval - before;
    if (a.stage == SGKeepAliveStageRefinedGrowth)
        CHECK(delta >= REFINE_LO && delta <= REFINE_HI, "refined climb %f", delta);
    else
        CHECK(a.stage == SGKeepAliveStageInitialGrowth, "unexpected stage %d", a.stage);
}

static void test_reset_action(void) {
    SGKeepAliveAlgorithm a;
    SGKeepAlive_Initialize(&a, true, 0.0);
    feed(&a, SGKeepAliveActionSuccess, 40);
    SGKeepAlive_ProcessAction(&a, SGKeepAliveActionReset);
    CHECK(a.currentInterval == MIN, "reset not to min: %f", a.currentInterval);
    CHECK(a.stage == SGKeepAliveStageSteadyState, "reset not steady: %d", a.stage);
}

static void test_reprobe_delay(void) {
    SGKeepAliveAlgorithm a;
    SGKeepAlive_Initialize(&a, true, INITIAL);
    CHECK(SGKeepAlive_SteadyStateReprobeDelay(&a) == 21600.0, "reprobe @900: %f",
          SGKeepAlive_SteadyStateReprobeDelay(&a));
    SGKeepAlive_Initialize(&a, true, 0.0);
    CHECK(SGKeepAlive_SteadyStateReprobeDelay(&a) == 0.0, "reprobe when not steady should be 0");
}

static void test_null_safety(void) {
    SGKeepAlive_Initialize(NULL, true, 0.0);
    SGKeepAlive_ProcessAction(NULL, SGKeepAliveActionSuccess);
    SGKeepAlive_ProcessHeartbeatResult(NULL, true);
    CHECK(SGKeepAlive_GetCurrentInterval(NULL) == INITIAL, "NULL default");
    CHECK(SGKeepAlive_SteadyStateReprobeDelay(NULL) == 0.0, "NULL reprobe");
}

int main(void) {
    test_init_bounds_and_warm_start();
    test_growth_step_and_cap();
    test_wwan_cap();
    test_steady_failure_backs_off_by_half();
    test_backoff_clamps_to_min();
    test_backoff_recovers_to_growth();
    test_initial_failure_enters_refined_growth();
    test_refined_growth_climbs_by_120();
    test_reset_action();
    test_reprobe_delay();
    test_null_safety();

    if (failures == 0) { printf("OK - all keepalive strategy tests passed\n"); return 0; }
    printf("%d FAILURE(S)\n", failures);
    return 1;
}
