#include "SGConnectionPolicy.h"
#include <stddef.h>

typedef struct {
    SGState from;
    SGState to;
} SGTransition;

static const SGTransition kLegalTransitions[] = {
    { SGStateResolvingDNS,       SGStateResolvingDNS         },
    { SGStateResolvingDNS,       SGStateConnecting           },
    { SGStateResolvingDNS,       SGStateBackingOff           },
    { SGStateResolvingDNS,       SGStateIdleCircuitOpen      },
    { SGStateResolvingDNS,       SGStateIdleNoNetwork        },

    { SGStateIdleNoNetwork,      SGStateConnecting           },
    { SGStateIdleNoNetwork,      SGStateResolvingDNS         },

    { SGStateIdleUnregistered,   SGStateResolvingDNS         },

    { SGStateConnecting,         SGStateResolvingDNS         },
    { SGStateConnecting,         SGStateAuthenticating       },
    { SGStateConnecting,         SGStateRegistering          },
    { SGStateConnecting,         SGStateBackingOff           },
    { SGStateConnecting,         SGStateIdleNoNetwork        },
    { SGStateConnecting,         SGStateIdleCircuitOpen      },

    { SGStateRegistering,        SGStateAuthenticating       },
    { SGStateRegistering,        SGStateBackingOff           },
    { SGStateRegistering,        SGStateIdleCircuitOpen      },
    { SGStateRegistering,        SGStateIdleNoNetwork        },
    { SGStateRegistering,        SGStateErrorVersionMismatch },

    { SGStateAuthenticating,     SGStateResolvingDNS         },
    { SGStateAuthenticating,     SGStateRegistering          },
    { SGStateAuthenticating,     SGStateConnected            },
    { SGStateAuthenticating,     SGStateBackingOff           },
    { SGStateAuthenticating,     SGStateIdleCircuitOpen      },
    { SGStateAuthenticating,     SGStateErrorAuth            },
    { SGStateAuthenticating,     SGStateIdleNoNetwork        },
    { SGStateAuthenticating,     SGStateErrorVersionMismatch },

    { SGStateConnected,          SGStateConnecting           },
    { SGStateConnected,          SGStateBackingOff           },
    { SGStateConnected,          SGStateIdleCircuitOpen      },
    { SGStateConnected,          SGStateIdleNoNetwork        },
    { SGStateConnected,          SGStateResolvingDNS         },
    { SGStateConnected,          SGStateErrorAuth            },
    { SGStateConnected,          SGStateErrorVersionMismatch },

    { SGStateBackingOff,         SGStateConnecting           },
    { SGStateBackingOff,         SGStateResolvingDNS         },
    { SGStateBackingOff,         SGStateIdleNoNetwork        },
    { SGStateBackingOff,         SGStateIdleCircuitOpen      },

    { SGStateIdleCircuitOpen,    SGStateConnecting           },
    { SGStateIdleCircuitOpen,    SGStateIdleNoNetwork        },
    { SGStateIdleCircuitOpen,    SGStateResolvingDNS         },

    { SGStateErrorAuth,          SGStateResolvingDNS         },
    { SGStateErrorBadConfig,     SGStateResolvingDNS         },
    { SGStateErrorVersionMismatch, SGStateResolvingDNS       },

    { SGStateDisabled,           SGStateResolvingDNS         },
};

bool SGConnectionTransitionIsLegal(SGState from, SGState to) {
    if (from == to || from == SGStateStarting) return true;

    if (to == SGStateDisabled ||
        to == SGStateIdleUnregistered ||
        to == SGStateErrorBadConfig) {
        return true;
    }

    for (size_t i = 0; i < sizeof(kLegalTransitions) / sizeof(kLegalTransitions[0]); i++) {
        if (kLegalTransitions[i].from == from && kLegalTransitions[i].to == to) {
            return true;
        }
    }
    return false;
}

bool SGConnectionStateNeedsActiveServices(SGState state) {
    switch (state) {
        case SGStateResolvingDNS:
        case SGStateConnecting:
        case SGStateRegistering:
        case SGStateAuthenticating:
        case SGStateConnected:
        case SGStateBackingOff:
        case SGStateIdleNoNetwork:
        case SGStateIdleCircuitOpen:
            return true;
        default:
            return false;
    }
}

SGState SGConnectionStateForConfiguration(bool enabled,
                                          bool hasProfile,
                                          bool valid,
                                          SGState currentState) {
    if (!enabled) return SGStateDisabled;
    if (!hasProfile) return SGStateIdleUnregistered;
    if (!valid) return SGStateErrorBadConfig;
    if (currentState == SGStateIdleNoNetwork) return SGStateIdleNoNetwork;
    return SGStateResolvingDNS;
}

uint32_t SGConnectionRetryDelay(unsigned int consecutiveFailures,
                                uint32_t jitterSeconds,
                                uint32_t serverRetryHint) {
    if (consecutiveFailures == 0) consecutiveFailures = 1;
    if (jitterSeconds > SG_MAX_JITTER_SECONDS) jitterSeconds = SG_MAX_JITTER_SECONDS;

    uint32_t delay = SG_INITIAL_BACKOFF_SECONDS;
    for (unsigned int i = 1;
         i < consecutiveFailures && delay < SG_MAX_BACKOFF_SECONDS;
         i++) {
        if (delay > SG_MAX_BACKOFF_SECONDS / 2) {
            delay = SG_MAX_BACKOFF_SECONDS;
        } else {
            delay *= 2;
        }
    }

    if (delay < SG_MAX_BACKOFF_SECONDS) {
        uint32_t room = SG_MAX_BACKOFF_SECONDS - delay;
        delay += (jitterSeconds < room) ? jitterSeconds : room;
    }

    if (serverRetryHint > delay) {
        delay = (serverRetryHint > SG_MAX_BACKOFF_SECONDS)
            ? SG_MAX_BACKOFF_SECONDS : serverRetryHint;
    }
    return delay;
}
