#ifndef SKYGLOW_SG_CONNECTION_POLICY_H
#define SKYGLOW_SG_CONNECTION_POLICY_H

#include <stdbool.h>
#include <stdint.h>
#include "SGStatus.h"

#define SG_INITIAL_BACKOFF_SECONDS  2
#define SG_MAX_BACKOFF_SECONDS      600
#define SG_MAX_JITTER_SECONDS       5
#define SG_CIRCUIT_TRIP_FAILURES    8
#define SG_CIRCUIT_FLOOR_SECONDS    3600
#define SG_RETRY_LEEWAY_PERCENT     10
#define SG_CIRCUIT_LEEWAY_PERCENT   50

/**
 * Pure connection,state policy. Keeping these decisions free of Foundation,
 * cuz im lazy and its easier to test :).
 */
bool SGConnectionTransitionIsLegal(SGState from, SGState to);

/** Whether this state needs reachability, power, retry, and keepalive services. */
bool SGConnectionStateNeedsActiveServices(SGState state);

/** Returns the state a configuration reload should select. */
SGState SGConnectionStateForConfiguration(bool enabled,
                                          bool hasProfile,
                                          bool valid,
                                          bool pathViable);

/** Computes exponential retry delay with jitter */
uint32_t SGConnectionRetryDelay(unsigned int consecutiveFailures,
                                uint32_t jitterSeconds,
                                uint32_t serverRetryHint);

typedef enum {
    SGFailureClassTransport = 0,
    SGFailureClassDNS       = 1,
    SGFailureClassPath      = 2,
} SGFailureClass;

/** Maps a socket-stage errno to its failure class. */
SGFailureClass SGFailureClassForOSError(int osError);

typedef struct {
    SGState  state;
    uint32_t delaySeconds;
    bool     countsAsFailure;
} SGConnectionRecovery;

/**
 * Every failure maps to a state that either holds a
 * guaranteed signal subscription (IdleNoNetwork) or a scheduled next attempt.
 * consecutiveFailures includes the failure being recovered from.
 */
SGConnectionRecovery SGConnectionRecoveryForFailure(SGFailureClass failureClass,
                                                    unsigned int consecutiveFailures,
                                                    bool pathViable,
                                                    uint32_t jitterSeconds,
                                                    uint32_t serverRetryHint);

#endif
