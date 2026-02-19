/*
 * StatusServer.c — Skyglow Notification Daemon
 *
 * See StatusServer.h for the public API and design rationale.
 *
 * Implementation notes:
 *
 *  - One background thread runs the accept loop. It blocks on accept()
 *    indefinitely. When a client connects it reads the 1-byte mode
 *    selector, handles it inline for QUERY, or registers the fd for
 *    WATCH. Watch fds are stored in a fixed array guarded by a mutex.
 *
 *  - StatusServer_post() holds the watcher mutex only long enough to
 *    snapshot the fd array, then releases it before doing any I/O.
 *    This prevents a slow/dead watcher from blocking state transitions
 *    in the daemon.
 *
 *  - A failed write to a watcher (EPIPE, EBADF, etc.) marks that slot
 *    as -1. Cleanup is deferred to the next broadcast or the accept
 *    thread's periodic sweep, whichever comes first.
 *
 *  - The accept thread is started with pthread_create and is the only
 *    thread that calls accept(). It exits cleanly when _serverFd is
 *    closed and accept() returns EBADF/EINVAL.
 *
 *  - All public functions are safe to call before StatusServer_start()
 *    returns (they check _running and no-op if false).
 */

#include "StatusServer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <time.h>

/* ─────────────────────────────────────────────────────────────────
 * Internal state
 * ───────────────────────────────────────────────────────────────── */

/// Set to 1 after StatusServer_start() succeeds.
static atomic_int           _running        = 0;

/// Listening socket fd. Closed by StatusServer_shutdown().
static int                  _serverFd       = -1;

/// Accept thread handle.
static pthread_t            _acceptThread;

/// Mutex protecting _watchers[] and _currentPayload.
static pthread_mutex_t      _lock           = PTHREAD_MUTEX_INITIALIZER;

/// Active watch client fds. -1 = empty slot.
static int                  _watchers[SS_MAX_WATCHERS];

/// Most recent payload. Served to QUERY clients and new WATCH clients.
static SGStatusPayload      _currentPayload;

/// Socket path saved at start (for unlink on shutdown).
static char                 _socketPath[256];


/* ─────────────────────────────────────────────────────────────────
 * Internal helpers
 * ───────────────────────────────────────────────────────────────── */

/// Write all bytes of buf to fd. Returns 0 on success, -1 on any error.
static int write_all(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        p         += n;
        remaining -= (size_t)n;
    }
    return 0;
}

/// Read exactly len bytes from fd into buf. Returns 0 on success, -1 on error/EOF.
static int read_exact(int fd, void *buf, size_t len) {
    char *p = (char *)buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = read(fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;   // EOF
        p         += n;
        remaining -= (size_t)n;
    }
    return 0;
}

/// Set fd to close-on-exec. Belt-and-suspenders: prevents fd leaking
/// into child processes if the daemon ever forks (it shouldn't, but be safe).
static void set_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags >= 0) fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

/// Build a fresh payload from current internal state.
/// Caller must hold _lock.
static SGStatusPayload build_payload_locked(SGState     state,
                                             uint32_t    failures,
                                             uint32_t    backoffSec,
                                             const char *serverIP) {
    SGStatusPayload p;
    memset(&p, 0, sizeof(p));
    p.magic              = SS_PAYLOAD_MAGIC;
    p.version            = SS_PAYLOAD_VERSION;
    p.state              = (uint8_t)state;
    p.timestamp          = (int64_t)time(NULL);
    p.startTime          = _currentPayload.startTime;   // preserved from start
    p.consecutiveFailures = failures;
    p.currentBackoffSec  = backoffSec;
    if (serverIP) {
        strlcpy(p.serverIP, serverIP, sizeof(p.serverIP));
    }
    return p;
}

/// Broadcast payload to all active watchers.
/// Caller must NOT hold _lock (we acquire it internally for the fd snapshot
/// to avoid holding it during I/O).
static void broadcast_payload(const SGStatusPayload *payload) {
    // Snapshot the watcher fds under the lock, then release before I/O.
    int snapshot[SS_MAX_WATCHERS];
    pthread_mutex_lock(&_lock);
    memcpy(snapshot, _watchers, sizeof(_watchers));
    pthread_mutex_unlock(&_lock);

    for (int i = 0; i < SS_MAX_WATCHERS; i++) {
        int fd = snapshot[i];
        if (fd < 0) continue;

        if (write_all(fd, payload, sizeof(*payload)) != 0) {
            // Write failed — client disconnected or died.
            // Mark the slot empty. Close the fd.
            close(fd);
            pthread_mutex_lock(&_lock);
            // Confirm it's still the same fd before clearing
            // (another thread could have reused the slot, though unlikely).
            if (_watchers[i] == fd) _watchers[i] = -1;
            pthread_mutex_unlock(&_lock);
        }
    }
}

/// Add a watch fd to the first available slot.
/// Returns 0 on success, -1 if the watcher table is full.
static int add_watcher(int fd) {
    pthread_mutex_lock(&_lock);
    for (int i = 0; i < SS_MAX_WATCHERS; i++) {
        if (_watchers[i] < 0) {
            _watchers[i] = fd;
            pthread_mutex_unlock(&_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&_lock);
    return -1;
}

/// Handle one incoming client connection. Called from the accept thread.
static void handle_client(int clientFd) {
    set_cloexec(clientFd);

    // Give the client 2 seconds to send its mode byte before we drop it.
    struct timeval tv = {2, 0};
    setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t mode = 0;
    if (read_exact(clientFd, &mode, 1) != 0) {
        // Timeout or error reading mode byte — drop the connection.
        close(clientFd);
        return;
    }

    // Remove read timeout for watch clients (we hold the fd open).
    tv.tv_sec = 0; tv.tv_usec = 0;
    setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (mode == SS_MODE_QUERY) {
        // ── Query: write current payload and close ──
        pthread_mutex_lock(&_lock);
        SGStatusPayload payload = _currentPayload;
        pthread_mutex_unlock(&_lock);

        // Stamp the timestamp fresh for the query response.
        payload.timestamp = (int64_t)time(NULL);
        write_all(clientFd, &payload, sizeof(payload));
        close(clientFd);

    } else if (mode == SS_MODE_WATCH) {
        // ── Watch: send current state immediately, then hold open ──
        pthread_mutex_lock(&_lock);
        SGStatusPayload payload = _currentPayload;
        pthread_mutex_unlock(&_lock);
        payload.timestamp = (int64_t)time(NULL);

        if (write_all(clientFd, &payload, sizeof(payload)) != 0) {
            // Client already gone.
            close(clientFd);
            return;
        }

        if (add_watcher(clientFd) != 0) {
            // Watcher table full — reject.
            // In practice this should never happen (8 slots for a status UI).
            fprintf(stderr, "[StatusServer] Watcher table full, rejecting client\n");
            close(clientFd);
        }
        // clientFd is now owned by the watchers table.
        // It will be closed by broadcast_payload() on the next failed write,
        // or by StatusServer_shutdown().

    } else {
        // Unknown mode byte — not our client.
        fprintf(stderr, "[StatusServer] Unknown mode byte 0x%02x, dropping\n", mode);
        close(clientFd);
    }
}

/// Accept loop — runs on _acceptThread for the lifetime of the daemon.
static void *accept_thread(void *arg) {
    (void)arg;

    while (1) {
        int clientFd = accept(_serverFd, NULL, NULL);
        if (clientFd < 0) {
            if (errno == EINTR)   continue;
            // EBADF / EINVAL means _serverFd was closed by shutdown.
            if (errno == EBADF || errno == EINVAL) break;
            fprintf(stderr, "[StatusServer] accept() error: %s\n", strerror(errno));
            // Brief pause to avoid spinning on a persistent error.
            usleep(100000);
            continue;
        }
        handle_client(clientFd);
    }

    return NULL;
}


/* ─────────────────────────────────────────────────────────────────
 * Public API implementation
 * ───────────────────────────────────────────────────────────────── */

int StatusServer_start(const char *socketPath, int64_t daemonStartTime) {
    if (atomic_load(&_running)) {
        fprintf(stderr, "[StatusServer] Already running\n");
        return 0;
    }

    if (!socketPath || socketPath[0] == '\0') {
        fprintf(stderr, "[StatusServer] Invalid socket path\n");
        return -1;
    }

    strlcpy(_socketPath, socketPath, sizeof(_socketPath));

    // Initialize watcher slots to empty.
    for (int i = 0; i < SS_MAX_WATCHERS; i++) _watchers[i] = -1;

    // Initialize current payload.
    memset(&_currentPayload, 0, sizeof(_currentPayload));
    _currentPayload.magic     = SS_PAYLOAD_MAGIC;
    _currentPayload.version   = SS_PAYLOAD_VERSION;
    _currentPayload.state     = (uint8_t)SGStateStarting;
    _currentPayload.startTime = daemonStartTime;
    _currentPayload.timestamp = (int64_t)time(NULL);

    // Remove any stale socket file from a previous run.
    unlink(socketPath);

    // Create the socket.
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "[StatusServer] socket() failed: %s\n", strerror(errno));
        return -1;
    }
    set_cloexec(fd);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strlcpy(addr.sun_path, socketPath, sizeof(addr.sun_path));

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[StatusServer] bind(%s) failed: %s\n", socketPath, strerror(errno));
        close(fd);
        return -1;
    }

    // Restrict to the daemon's own uid.
    chmod(socketPath, 0600);

    if (listen(fd, 8) < 0) {
        fprintf(stderr, "[StatusServer] listen() failed: %s\n", strerror(errno));
        close(fd);
        unlink(socketPath);
        return -1;
    }

    _serverFd = fd;
    atomic_store(&_running, 1);

    // Start the accept thread.
    int err = pthread_create(&_acceptThread, NULL, accept_thread, NULL);
    if (err != 0) {
        fprintf(stderr, "[StatusServer] pthread_create failed: %s\n", strerror(err));
        close(_serverFd);
        _serverFd = -1;
        unlink(socketPath);
        atomic_store(&_running, 0);
        return -1;
    }

    fprintf(stderr, "[StatusServer] Listening at %s\n", socketPath);
    return 0;
}

void StatusServer_post(SGState      state,
                       uint32_t     consecutiveFailures,
                       uint32_t     currentBackoffSec,
                       const char  *serverIP) {
    if (!atomic_load(&_running)) return;

    pthread_mutex_lock(&_lock);
    _currentPayload = build_payload_locked(state, consecutiveFailures,
                                           currentBackoffSec, serverIP);
    SGStatusPayload snapshot = _currentPayload;
    pthread_mutex_unlock(&_lock);

    broadcast_payload(&snapshot);
}

void StatusServer_current(SGStatusPayload *outPayload) {
    if (!outPayload) return;
    pthread_mutex_lock(&_lock);
    *outPayload = _currentPayload;
    pthread_mutex_unlock(&_lock);
    outPayload->timestamp = (int64_t)time(NULL);
}

void StatusServer_shutdown(void) {
    if (!atomic_load(&_running)) return;

    // Post shutdown state to all watchers before closing.
    StatusServer_post(SGStateShuttingDown, 0, 0, NULL);

    atomic_store(&_running, 0);

    // Close the listening socket. This causes accept() to return
    // EBADF/EINVAL in the accept thread, which exits the loop.
    if (_serverFd >= 0) {
        close(_serverFd);
        _serverFd = -1;
    }

    // Wait for the accept thread to exit.
    pthread_join(_acceptThread, NULL);

    // Close all remaining watch connections.
    pthread_mutex_lock(&_lock);
    for (int i = 0; i < SS_MAX_WATCHERS; i++) {
        if (_watchers[i] >= 0) {
            close(_watchers[i]);
            _watchers[i] = -1;
        }
    }
    pthread_mutex_unlock(&_lock);

    // Remove the socket file.
    if (_socketPath[0] != '\0') {
        unlink(_socketPath);
    }
}

const char *SGState_name(SGState state) {
    switch (state) {
        case SGStateStarting:            return "Starting";
        case SGStateDisabled:            return "Disabled";
        case SGStateIdleUnregistered:    return "IdleUnregistered";
        case SGStateResolvingDNS:        return "ResolvingDNS";
        case SGStateIdleDNSFailed:       return "IdleDNSFailed";
        case SGStateConnecting:          return "Connecting";
        case SGStateAuthenticating:      return "Authenticating";
        case SGStateConnected:           return "Connected";
        case SGStateBackingOff:          return "BackingOff";
        case SGStateIdleNoNetwork:       return "IdleNoNetwork";
        case SGStateIdleCircuitOpen:     return "IdleCircuitOpen";
        case SGStateErrorAuth:           return "ErrorAuth";
        case SGStateErrorBadConfig:      return "ErrorBadConfig";
        case SGStateError:               return "Error";
        case SGStateShuttingDown:        return "ShuttingDown";
        default:                         return "Unknown";
    }
}