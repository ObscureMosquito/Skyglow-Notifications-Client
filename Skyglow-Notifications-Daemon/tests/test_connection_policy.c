#include <stdio.h>
#include <errno.h>
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
    CHECK(SGConnectionStateForConfiguration(false, true, true, true) == SGStateDisabled,
          "disabled config did not win during connect");
    CHECK(SGConnectionStateForConfiguration(true, false, false, true) == SGStateIdleUnregistered,
          "missing profile did not become unregistered");
    CHECK(SGConnectionStateForConfiguration(true, true, false, true) == SGStateErrorBadConfig,
          "bad config did not become terminal config error");
    CHECK(SGConnectionStateForConfiguration(true, true, true, true) == SGStateResolvingDNS,
          "valid reload with viable path did not restart resolution");
    CHECK(SGConnectionStateForConfiguration(true, true, true, false) == SGStateIdleNoNetwork,
          "valid reload without viable path should park offline");
    CHECK(SGConnectionStateForConfiguration(false, true, true, false) == SGStateDisabled,
          "disabled must win over missing network");

    CHECK(SGConnectionTransitionIsLegal(SGStateIdleUnregistered, SGStateIdleNoNetwork),
          "fresh profile with no network cannot park offline");
    CHECK(SGConnectionTransitionIsLegal(SGStateDisabled, SGStateIdleNoNetwork),
          "enabling with no network cannot park offline");
    CHECK(SGConnectionTransitionIsLegal(SGStateErrorAuth, SGStateIdleNoNetwork),
          "auth-error reload with no network cannot park offline");
}

static void test_active_service_lifetime(void) {
    CHECK(SGConnectionStateNeedsActiveServices(SGStateResolvingDNS),
          "DNS resolution needs network services");
    CHECK(SGConnectionStateNeedsActiveServices(SGStateConnected),
          "connected state needs keepalive services");
    CHECK(SGConnectionStateNeedsActiveServices(SGStateIdleNoNetwork),
          "offline state needs reachability to recover");
    CHECK(!SGConnectionStateNeedsActiveServices(SGStateDisabled),
          "disabled state must not consume active services");
    CHECK(!SGConnectionStateNeedsActiveServices(SGStateIdleUnregistered),
          "unregistered state must not monitor power/network");
    CHECK(!SGConnectionStateNeedsActiveServices(SGStateErrorAuth),
          "terminal auth error must not consume active services");
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

static void test_os_error_classification(void) {
    CHECK(SGFailureClassForOSError(ENETUNREACH) == SGFailureClassPath,
          "no-route errno did not classify as path");
    CHECK(SGFailureClassForOSError(ENETDOWN) == SGFailureClassPath,
          "network-down errno did not classify as path");
    CHECK(SGFailureClassForOSError(EHOSTUNREACH) == SGFailureClassPath,
          "host-unreachable errno did not classify as path");
    CHECK(SGFailureClassForOSError(ECONNREFUSED) == SGFailureClassTransport,
          "refused connection must stay on the retry curve");
    CHECK(SGFailureClassForOSError(ETIMEDOUT) == SGFailureClassTransport,
          "timeout must stay on the retry curve");
    CHECK(SGFailureClassForOSError(0) == SGFailureClassTransport,
          "absent OS error must default to transport");
}

static void test_recovery_parks_when_path_is_gone(void) {
    SGConnectionRecovery recovery;

    recovery = SGConnectionRecoveryForFailure(SGFailureClassPath, 1, true, 0, 0);
    CHECK(recovery.state == SGStateIdleNoNetwork, "no-route failure did not park");
    CHECK(!recovery.countsAsFailure, "no-route failure polluted the streak");
    CHECK(recovery.delaySeconds == 0, "parked state must not need a timer");

    recovery = SGConnectionRecoveryForFailure(SGFailureClassTransport, 3, false, 0, 0);
    CHECK(recovery.state == SGStateIdleNoNetwork, "unviable path did not park");
    CHECK(!recovery.countsAsFailure, "unviable-path failure polluted the streak");
}

static void test_recovery_backs_off_then_trips_circuit(void) {
    SGConnectionRecovery recovery;

    for (unsigned int streak = 1; streak < SG_CIRCUIT_TRIP_FAILURES; streak++) {
        recovery = SGConnectionRecoveryForFailure(SGFailureClassTransport, streak, true, 0, 0);
        CHECK(recovery.state == SGStateBackingOff, "streak %u left the backoff regime", streak);
        CHECK(recovery.delaySeconds == SGConnectionRetryDelay(streak, 0, 0),
              "streak %u delay diverged from retry curve", streak);
        CHECK(recovery.countsAsFailure, "backoff failure must count");
    }

    recovery = SGConnectionRecoveryForFailure(SGFailureClassDNS, SG_CIRCUIT_TRIP_FAILURES, true, 0, 0);
    CHECK(recovery.state == SGStateIdleCircuitOpen, "trip threshold did not open circuit");
    CHECK(recovery.delaySeconds == SG_CIRCUIT_FLOOR_SECONDS, "circuit floor mismatch");

    recovery = SGConnectionRecoveryForFailure(SGFailureClassTransport, 5000, true, 0, 0);
    CHECK(recovery.state == SGStateIdleCircuitOpen, "deep streak fell out of circuit regime");

    recovery = SGConnectionRecoveryForFailure(SGFailureClassTransport, 2, true, 0, 120);
    CHECK(recovery.delaySeconds == 120, "server retry hint was not honored in backoff");
}

static void test_recovery_always_schedules_or_parks(void) {
    const SGFailureClass classes[] = {
        SGFailureClassTransport, SGFailureClassDNS, SGFailureClassPath,
    };
    for (unsigned int c = 0; c < sizeof(classes) / sizeof(classes[0]); c++) {
        for (unsigned int streak = 1; streak <= SG_CIRCUIT_TRIP_FAILURES * 3; streak++) {
            for (int viable = 0; viable <= 1; viable++) {
                SGConnectionRecovery recovery =
                    SGConnectionRecoveryForFailure(classes[c], streak, viable != 0, 0, 0);
                CHECK(recovery.state == SGStateIdleNoNetwork ||
                      recovery.state == SGStateBackingOff ||
                      recovery.state == SGStateIdleCircuitOpen,
                      "class %u streak %u produced non-retry state", classes[c], streak);
                CHECK(recovery.state == SGStateIdleNoNetwork || recovery.delaySeconds > 0,
                      "class %u streak %u has neither signal nor timer", classes[c], streak);
                CHECK(recovery.delaySeconds <= SG_CIRCUIT_FLOOR_SECONDS,
                      "class %u streak %u delay escaped the floor cap", classes[c], streak);
            }
        }
    }
}

int main(void) {
    test_administrative_states_are_always_reachable();
    test_configuration_routing();
    test_active_service_lifetime();
    test_retry_never_stops_and_stays_bounded();
    test_os_error_classification();
    test_recovery_parks_when_path_is_gone();
    test_recovery_backs_off_then_trips_circuit();
    test_recovery_always_schedules_or_parks();

    if (failures == 0) {
        printf("OK - all connection policy tests passed\n");
        return 0;
    }
    printf("%d FAILURE(S)\n", failures);
    return 1;
}
