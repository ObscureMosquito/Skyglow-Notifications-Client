#include "SGStatusServer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#define SS_MAX_WATCHERS 16
#define SS_MODE_QUERY 0x51 // 'Q'
#define SS_MODE_WATCH 0x57 // 'W'

static SGStatusPayload _current;
static pthread_mutex_t  _lock = PTHREAD_MUTEX_INITIALIZER;
static int              _serverFd = -1;
static int              _watchers[SS_MAX_WATCHERS];
static pthread_t        _acceptThread;
static char             _socketPath[1024];
static int              _running = 0;

static void* SGStatusServer_AcceptLoop(void* arg) {
    while (_running) {
        struct sockaddr_un clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        int clientFd = accept(_serverFd, (struct sockaddr*)&clientAddr, &clientLen);
        
        if (clientFd < 0) {
            if (errno == EMFILE || errno == ENFILE) {
                sleep(1);
            } else if (errno == EINTR) {
                continue;
            }
            break;
        }

        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(clientFd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        uint8_t mode = 0;
        if (read(clientFd, &mode, 1) != 1) {
            close(clientFd);
            continue;
        }

        if (mode == SS_MODE_QUERY) {
            int flags = fcntl(clientFd, F_GETFL, 0);
            fcntl(clientFd, F_SETFL, flags | O_NONBLOCK);
            pthread_mutex_lock(&_lock);
            SGStatusPayload snap = _current;
            pthread_mutex_unlock(&_lock);
            write(clientFd, &snap, sizeof(snap));
            close(clientFd);
        } else if (mode == SS_MODE_WATCH) {
            pthread_mutex_lock(&_lock);
            SGStatusPayload snap = _current;
            int added = 0;
            int addedIdx = -1;
            for (int i = 0; i < SS_MAX_WATCHERS; i++) {
                if (_watchers[i] < 0) {
                    _watchers[i] = clientFd;
                    added = 1;
                    addedIdx = i;
                    break;
                }
            }
            pthread_mutex_unlock(&_lock);

            if (added) {
                if (write(clientFd, &snap, sizeof(snap)) != sizeof(snap)) {
                    close(clientFd);
                    pthread_mutex_lock(&_lock);
                    _watchers[addedIdx] = -1;
                    pthread_mutex_unlock(&_lock);
                }
            } else {
                close(clientFd);
            }
        } else {
            close(clientFd);
        }
    }
    return NULL;
}

void SGStatusServer_Start(const char *socketPath, int64_t startTime) {
    pthread_mutex_lock(&_lock);
    if (_running) { pthread_mutex_unlock(&_lock); return; }
    
    _current.daemonStartTime = startTime;
    _current.lastStateTransitionTime = startTime;
    _current.state = SGStateStarting;
    
    for (int i = 0; i < SS_MAX_WATCHERS; i++) _watchers[i] = -1;
    strncpy(_socketPath, socketPath, sizeof(_socketPath)-1);

    _serverFd = socket(AF_UNIX, SOCK_STREAM, 0);
    unlink(_socketPath);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, _socketPath, sizeof(addr.sun_path)-1);

    if (bind(_serverFd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(_serverFd); _serverFd = -1;
        pthread_mutex_unlock(&_lock);
        return;
    }

    listen(_serverFd, 5);
    chmod(_socketPath, 0660);
    chown(_socketPath, 0, 501);
    
    _running = 1;
    pthread_create(&_acceptThread, NULL, SGStatusServer_AcceptLoop, NULL);
    pthread_mutex_unlock(&_lock);
}

void SGStatusServer_Post(SGState state, uint32_t failures, uint32_t backoff, const char *ip) {
    pthread_mutex_lock(&_lock);
    _current.state = state;
    _current.consecutiveFailures = failures;
    _current.currentBackoffSec = backoff;
    _current.lastStateTransitionTime = (int64_t)time(NULL);
    if (ip) strncpy(_current.serverIP, ip, sizeof(_current.serverIP)-1);
    
    SGStatusPayload snapshot = _current;
    int snapshotWatchers[SS_MAX_WATCHERS];
    memcpy(snapshotWatchers, _watchers, sizeof(_watchers));
    pthread_mutex_unlock(&_lock);

    for (int i = 0; i < SS_MAX_WATCHERS; i++) {
        if (snapshotWatchers[i] >= 0) {
            if (write(snapshotWatchers[i], &snapshot, sizeof(snapshot)) != sizeof(snapshot)) {
                close(snapshotWatchers[i]);
                pthread_mutex_lock(&_lock); 
                _watchers[i] = -1; 
                pthread_mutex_unlock(&_lock);
            }
        }
    }
}

void SGStatusServer_Current(SGStatusPayload *outPayload) {
    pthread_mutex_lock(&_lock);
    if (outPayload) *outPayload = _current;
    pthread_mutex_unlock(&_lock);
}

void SGStatusServer_Shutdown(void) {
    pthread_mutex_lock(&_lock);
    _running = 0;
    if (_serverFd >= 0) {
        shutdown(_serverFd, SHUT_RDWR);
        close(_serverFd);
        _serverFd = -1;
    }
    pthread_mutex_unlock(&_lock);
    
    pthread_join(_acceptThread, NULL);
    unlink(_socketPath);
}

const char *SGState_GetName(SGState state) {
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
        case SGStateRegistering:         return "Registering";
        default:                         return "Unknown";
    }
}