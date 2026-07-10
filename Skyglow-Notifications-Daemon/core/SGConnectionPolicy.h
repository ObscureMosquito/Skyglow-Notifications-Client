#ifndef SKYGLOW_SG_CONNECTION_POLICY_H
#define SKYGLOW_SG_CONNECTION_POLICY_H

#include <stdbool.h>
#include <stdint.h>
#include "SGStatusServer.h"

#define SG_INITIAL_BACKOFF_SECONDS  2
#define SG_MAX_BACKOFF_SECONDS      600
#define SG_MAX_JITTER_SECONDS       5

/**
 * Pure connection-state policy. Keeping these decisions free of Foundation,
 * sockets, and timers makes the daemon's reliability rules directly testable.
 */
bool SGConnectionTransitionIsLegal(SGState from, SGState to);

/**
 * Returns the state a configuration reload should select. A valid reload keeps
 * an explicitly offline daemon offline; every other valid state starts a fresh
 * resolution cycle.
 */
SGState SGConnectionStateForConfiguration(bool enabled,
                                          bool hasProfile,
                                          bool valid,
                                          SGState currentState);

/**
 * Computes exponential retry delay with jitter. Both locally-computed delay
 * and a server retry hint are capped so no peer can suppress reconnects
 * indefinitely. Once the cap is reached, retries continue at the cap forever.
 */
uint32_t SGConnectionRetryDelay(unsigned int consecutiveFailures,
                                uint32_t jitterSeconds,
                                uint32_t serverRetryHint);

#endif
