#ifndef SKYGLOW_STATUSSERVER_H
#define SKYGLOW_STATUSSERVER_H

/*
 * StatusServer.h — Skyglow Notification Daemon
 *
 * Lightweight Unix domain socket server that exposes daemon state to
 * local clients (settings UI, widgets, diagnostic tools).
 *
 * Two client modes, selected by the first byte sent after connect:
 *
 *   QUERY (0x51):  Daemon writes one SGStatusPayload, then closes the
 *                  connection. Caller gets current state instantly.
 *
 *   WATCH (0x57):  Daemon writes one SGStatusPayload immediately (current
 *                  state), then writes a new one on every state transition.
 *                  Connection is held until the client closes it or a write
 *                  fails (client died). At most SS_MAX_WATCHERS simultaneous
 *                  watch connections are served.
 *
 * All payloads are fixed-size binary structs (no framing needed).
 * The socket is created with mode 0600, owned by the daemon's uid,
 * so only processes running as the same user can connect.
 *
 * Pure C — no Objective-C, no Foundation, no autorelease pool dependency.
 * Safe to call from any thread at any time after StatusServer_start().
 *
 * Typical call sites:
 *   main()               → StatusServer_start(SS_SOCKET_PATH)
 *   transitionToState()  → StatusServer_post(newState, failures, serverIP, startTime)
 *   main() teardown      → StatusServer_shutdown()
 */

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─────────────────────────────────────────────────────────────────
 * Constants
 * ───────────────────────────────────────────────────────────────── */

/// Default socket path. Must be writable by the daemon's uid.
#define SS_SOCKET_PATH      "/var/run/skyglow_snd.sock"

/// Magic bytes that select client mode.
#define SS_MODE_QUERY       ((uint8_t)0x51)
#define SS_MODE_WATCH       ((uint8_t)0x57)

/// Maximum simultaneous watch connections.
/// The settings UI is typically the only watcher; 8 gives headroom.
#define SS_MAX_WATCHERS     8

/// Seconds a watch client may be silent (no read from our side means
/// we detect death only on the next broadcast write). We don't actively
/// time out watch clients on idle — we rely on EPIPE/write failure.
/// This constant is reserved for future use if a keepalive is added.
#define SS_WATCH_IDLE_MAX   300

/// Magic prefix written at the start of every payload so clients can
/// verify they are reading a well-formed response and not garbage.
/// Two bytes: 0x5347 ("SG").
#define SS_PAYLOAD_MAGIC    ((uint16_t)0x5347)

/// Current payload version. Increment if SGStatusPayload layout changes.
#define SS_PAYLOAD_VERSION  ((uint8_t)1)


/* ─────────────────────────────────────────────────────────────────
 * State enum
 *
 * These are the only legal daemon states. Every transition must be
 * through StatusServer_post(). No state exists outside this enum.
 * ───────────────────────────────────────────────────────────────── */

typedef enum : uint8_t {

    /// Daemon has just started; no state determined yet.
    SGStateStarting                 = 0,

    /// Daemon is administratively disabled (enabled=NO in prefs).
    SGStateDisabled                 = 1,

    /// Enabled but device is not registered (no device_address in profile).
    SGStateIdleUnregistered         = 2,

    /// Performing DNS TXT lookup for server IP/port.
    SGStateResolvingDNS             = 3,

    /// DNS failed after all retries; waiting for config reload or timer.
    SGStateIdleDNSFailed            = 4,

    /// TCP + TLS connection in progress.
    SGStateConnecting               = 5,

    /// TCP+TLS up; waiting for server Hello / challenge exchange.
    SGStateAuthenticating           = 6,

    /// Fully connected and authenticated; receiving notifications.
    SGStateConnected                = 7,

    /// Transient: connection lost, waiting before next attempt.
    SGStateBackingOff               = 8,

    /// Network is not reachable; waiting for reachability callback.
    SGStateIdleNoNetwork            = 9,

    /// Too many rapid failures; circuit open, waiting for timer or reload.
    SGStateIdleCircuitOpen          = 10,

    /// Server certificate / auth rejected. Requires config intervention.
    SGStateErrorAuth                = 11,

    /// Server address / port is malformed or missing.
    SGStateErrorBadConfig           = 12,

    /// Unrecoverable internal error (db init failed, etc.).
    SGStateError                    = 13,

    /// Clean shutdown in progress.
    SGStateShuttingDown             = 14,

    /// First-time setup: C_REGISTER sent, waiting for S_CHALLENGE/S_REGISTER_OK/FAIL.
    /// On S_REGISTER_OK the profile is persisted and C_LOGIN is sent immediately
    /// on the same connection (server resets to CONNECTED state after REGISTER_OK).
    SGStateRegistering              = 15,

} SGState;

/* ─────────────────────────────────────────────────────────────────
 * Status Payload
 * * Sent to WATCH clients on every state transition, and QUERY clients
 * immediately upon connection.
 *
 * Fields are explicitly ordered largest-to-smallest to guarantee
 * natural memory alignment (multiples of 8 bytes for int64_t) to
 * prevent EXC_BAD_ACCESS hardware traps on ARMv6/ARMv7 (iOS 4/5/6).
 * ───────────────────────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    uint16_t    magic;               // Offset: 0
    uint8_t     version;             // Offset: 2
    uint8_t     state;               // Offset: 3 (SGState enum)
    uint8_t     padding1[4];         // Offset: 4 (Pads to 8 bytes to align the next field)
    int64_t     timestamp;           // Offset: 8 (Perfectly Aligned to 8)
    int64_t     startTime;           // Offset: 16 (Perfectly Aligned to 8)
    uint32_t    consecutiveFailures; // Offset: 24 (Aligned to 4)
    uint32_t    currentBackoffSec;   // Offset: 28 (Aligned to 4)
    char        serverIP[64];        // Offset: 32 (Total struct size = 96 bytes)
} SGStatusPayload;
#pragma pack(pop)

/* ─────────────────────────────────────────────────────────────────
 * Public API
 * ───────────────────────────────────────────────────────────────── */

/**
 * Start the status server.
 *
 * Creates the Unix domain socket at @p socketPath, sets permissions
 * to 0600, and starts the accept thread. Returns immediately.
 *
 * @param socketPath  Filesystem path for the socket file.
 *                    Pass SS_SOCKET_PATH for the default.
 * @param daemonStartTime  time(NULL) captured at daemon entry — stored
 *                         in every payload for uptime calculation.
 * @return  0 on success, -1 on failure (check errno / logs).
 *
 * Must be called once from main() before any state transitions.
 * Thread-safe after initial call.
 */
int StatusServer_start(const char *socketPath, int64_t daemonStartTime);

/**
 * Post a state transition.
 *
 * Updates internal state and broadcasts an SGStatusPayload to all
 * active watch clients immediately. Thread-safe; may be called from
 * any thread.
 *
 * @param state              New daemon state.
 * @param consecutiveFailures Current failure count (0 if connected).
 * @param currentBackoffSec  Current backoff delay (0 if not backing off).
 * @param serverIP           Current server IP string, or NULL.
 */
void StatusServer_post(SGState      state,
                       uint32_t     consecutiveFailures,
                       uint32_t     currentBackoffSec,
                       const char  *serverIP);

/**
 * Retrieve the current status payload without going through the socket.
 * Useful for daemon-internal diagnostics. Thread-safe.
 *
 * @param outPayload  Filled with the current payload on return.
 */
void StatusServer_current(SGStatusPayload *outPayload);

/**
 * Shut down the status server.
 *
 * Closes the listening socket, broadcasts SGStateShuttingDown to all
 * watch clients, then closes all watcher connections. Blocks until the
 * accept thread exits (should be near-instant after close).
 *
 * Call from main() during clean teardown only.
 */
void StatusServer_shutdown(void);

/**
 * Human-readable name for a state, for logging.
 * Returns a string literal; do not free.
 */
const char *SGState_name(SGState state);


#ifdef __cplusplus
}
#endif

#endif /* SKYGLOW_STATUSSERVER_H */