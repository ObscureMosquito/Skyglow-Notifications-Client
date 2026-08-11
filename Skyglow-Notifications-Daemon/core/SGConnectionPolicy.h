#ifndef SKYGLOW_SG_CONNECTION_POLICY_H
#define SKYGLOW_SG_CONNECTION_POLICY_H

#include <stdbool.h>
#include <stdint.h>
#include "SGStatusServer.h"

#define SG_INITIAL_BACKOFF_SECONDS  2
#define SG_MAX_BACKOFF_SECONDS      600
#define SG_MAX_JITTER_SECONDS       5

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
                                          SGState currentState);

/** Computes exponential retry delay with jitter */
uint32_t SGConnectionRetryDelay(unsigned int consecutiveFailures,
                                uint32_t jitterSeconds,
                                uint32_t serverRetryHint);

#endif
