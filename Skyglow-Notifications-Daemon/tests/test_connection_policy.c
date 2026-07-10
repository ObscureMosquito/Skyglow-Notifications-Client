#include <stdio.h>
#include "SGConnectionPolicy.h"

static int failures = 0;
#define CHECK(condition, ...) do { if (!(condition)) { \
    failures++; printf("FAIL %s:%d  %s\n      ", __func__, __LINE__, #condition); \
    printf(__VA_ARGS__); printf("\n"); } } while (0)

static void test_administrative_states_are_always_reachable(void) {
    const SGState states[] = {
        SGStateStarting, SGStateDisabled, SGStateIdleUnregistered,
        SGStateResolvingDNS, SGStateConnecting, SGStateAuthenticating,
        SGStateConnected, SGStateBackingOff, SGStateIdleNoNetwork,
        SGStateIdleCircuitOpen, SGStateErrorAuth, SGStateErrorBadConfig,
        SGStateRegistering, SGStateErrorVersionMismatch,
    };

    for (unsigned int i = 0; i < sizeof(states) / sizeof(states[0]); i++) {
        CHECK(SGConnectionTransitionIsLegal(states[i], SGStateDisabled),
              "state %u cannot disable", (unsigned)states[i]);
        CHECK(SGConnectionTransitionIsLegal(states[i], SGStateIdleUnregistered),
              "state %u cannot become unregistered", (unsigned)states[i]);
        CHECK(SGConnectionTransitionIsLegal(states[i], SGStateErrorBadConfig),
              "state %u cannot reject bad config", (unsigned)states[i]);
    }

    CHECK(!SGConnectionTransitionIsLegal(SGStateDisabled, SGStateConnected),
          "disabled must not jump directly to connected");
}

static void test_configuration_routing(void) {
    CHECK(SGConnectionStateForConfiguration(false, true, true, SGStateConnecting) == SGStateDisabled,
          "disabled config did not win during connect");
    CHECK(SGConnectionStateForConfiguration(true, false, false, SGStateConnected) == SGStateIdleUnregistered,
          "missing profile did not become unregistered");
    CHECK(SGConnectionStateForConfiguration(true, true, false, SGStateBackingOff) == SGStateErrorBadConfig,
          "bad config did not become terminal config error");
    CHECK(SGConnectionStateForConfiguration(true, true, true, SGStateConnected) == SGStateResolvingDNS,
          "valid live reload did not restart resolution");
    CHECK(SGConnectionStateForConfiguration(true, true, true, SGStateIdleNoNetwork) == SGStateIdleNoNetwork,
          "offline reload should remain offline");
}

static void test_retry_never_stops_and_stays_bounded(void) {
    CHECK(SGConnectionRetryDelay(1, 0, 0) == 2, "first retry mismatch");
    CHECK(SGConnectionRetryDelay(1, SG_MAX_JITTER_SECONDS, 0) == 7,
          "first retry jitter mismatch");
    CHECK(SGConnectionRetryDelay(9, 0, 0) == 512, "ninth retry mismatch");
    CHECK(SGConnectionRetryDelay(10, 0, 0) == SG_MAX_BACKOFF_SECONDS,
          "retry did not reach cap");
    CHECK(SGConnectionRetryDelay(1000000, SG_MAX_JITTER_SECONDS, 0) == SG_MAX_BACKOFF_SECONDS,
          "long-running retry escaped cap");
    CHECK(SGConnectionRetryDelay(2, 0, 120) == 120,
          "reasonable server hint was not honored");
    CHECK(SGConnectionRetryDelay(2, 0, UINT32_MAX) == SG_MAX_BACKOFF_SECONDS,
          "server hint could suppress retries indefinitely");
}

int main(void) {
    test_administrative_states_are_always_reachable();
    test_configuration_routing();
    test_retry_never_stops_and_stays_bounded();

    if (failures == 0) {
        printf("OK - all connection policy tests passed\n");
        return 0;
    }
    printf("%d FAILURE(S)\n", failures);
    return 1;
}
