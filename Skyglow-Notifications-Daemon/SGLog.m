#import "SGLog.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

/**
 * State for the logger is all file-static and guarded by _logLock.
 * Keeping it static rather than wrapping in an object avoids any
 * ARC/MRC asymmetry — this file is compiled MRC in the daemon, and the
 * same .o could be compiled ARC elsewhere without behavioural change.
 */
static pthread_mutex_t _logLock = PTHREAD_MUTEX_INITIALIZER;

static SGLogLevel _minLevel    = SGLogLevelInfo;
static FILE      *_logFile     = NULL;
static char       _logPath[1024]    = {0};
static size_t     _rotateBytes      = 0;
static size_t     _bytesWritten     = 0;   /* since last open/rotate */
static char       _procName[32]     = {0};
static int        _syslogOpened     = 0;

/* ASCII letter for each level — kept short for grep-friendly output. */
static const char _levelChars[] = { 'E', 'W', 'I', 'D', 'T' };

/* syslog priority mirror for each level.  Debug/Trace are not mirrored. */
static const int _syslogPriorities[] = {
    LOG_ERR,      /* SGLogLevelError */
    LOG_WARNING,  /* SGLogLevelWarn  */
    LOG_INFO,     /* SGLogLevelInfo  */
    -1,           /* SGLogLevelDebug — file only */
    -1,           /* SGLogLevelTrace — file only */
};

/**
 * Rotate the current file when it exceeds _rotateBytes.
 * Caller MUST hold _logLock.
 *
 * Strategy: rename current file to "<path>.1" (overwriting any previous .1),
 * then open a fresh file at <path>.  We keep exactly two generations on
 * disk — current and previous — which is enough to retain context across
 * one rotation without unbounded growth on storage-constrained devices.
 *
 * If rename or reopen fails we drop the file backend and continue with
 * syslog only.  Losing the file is preferable to crashing the daemon.
 */
static void SG_RotateLocked(void) {
    if (!_logFile || _rotateBytes == 0 || _logPath[0] == '\0') return;

    fflush(_logFile);
    fclose(_logFile);
    _logFile = NULL;

    char rotated[1024];
    if ((size_t)snprintf(rotated, sizeof(rotated), "%s.1", _logPath) >= sizeof(rotated)) {
        return;
    }

    /* rename() is atomic on the same filesystem and replaces an existing target. */
    (void)rename(_logPath, rotated);

    _logFile = fopen(_logPath, "a");
    if (_logFile) {
        (void)fchmod(fileno(_logFile), 0644);
        _bytesWritten = 0;
    }
}

/**
 * Format the timestamp prefix into `out`.  Returns bytes written (excluding
 * the trailing NUL).  Uses gettimeofday + localtime_r so we get millisecond
 * precision without dragging in NSDateFormatter.
 *
 * Format: "2026-05-22 14:03:21.482"
 */
static size_t SG_FormatTimestamp(char *out, size_t outLen) {
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) {
        return (size_t)snprintf(out, outLen, "0000-00-00 00:00:00.000");
    }

    struct tm tmval;
    time_t secs = (time_t)tv.tv_sec;
    localtime_r(&secs, &tmval);

    size_t n = strftime(out, outLen, "%Y-%m-%d %H:%M:%S", &tmval);
    if (n == 0 || n >= outLen) return n;

    int extra = snprintf(out + n, outLen - n, ".%03d", (int)(tv.tv_usec / 1000));
    if (extra < 0) return n;
    return n + (size_t)extra;
}

void SGLog_SetMinLevel(SGLogLevel level) {
    if (level < SGLogLevelError) level = SGLogLevelError;
    if (level > SGLogLevelTrace) level = SGLogLevelTrace;
    pthread_mutex_lock(&_logLock);
    _minLevel = level;
    pthread_mutex_unlock(&_logLock);
}

SGLogLevel SGLog_GetMinLevel(void) {
    pthread_mutex_lock(&_logLock);
    SGLogLevel l = _minLevel;
    pthread_mutex_unlock(&_logLock);
    return l;
}

void SGLog_SetProcessName(const char *name) {
    pthread_mutex_lock(&_logLock);
    if (name && name[0] != '\0') {
        strncpy(_procName, name, sizeof(_procName) - 1);
        _procName[sizeof(_procName) - 1] = '\0';
        if (!_syslogOpened) {
            /* openlog's `ident` argument is borrowed, not copied — keep a
             * stable backing buffer (_procName) for its lifetime. */
            openlog(_procName, LOG_PID | LOG_NDELAY, LOG_DAEMON);
            _syslogOpened = 1;
        }
    }
    pthread_mutex_unlock(&_logLock);
}

int SGLog_OpenFile(const char *path, size_t rotateBytes) {
    if (!path || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    pthread_mutex_lock(&_logLock);

    if (_logFile) {
        fflush(_logFile);
        fclose(_logFile);
        _logFile = NULL;
    }

    strncpy(_logPath, path, sizeof(_logPath) - 1);
    _logPath[sizeof(_logPath) - 1] = '\0';
    _rotateBytes  = rotateBytes;
    _bytesWritten = 0;

    _logFile = fopen(_logPath, "a");
    int rc = 0;
    if (!_logFile) {
        rc = -1;
    } else {
        (void)fchmod(fileno(_logFile), 0644);

        /* Seed _bytesWritten from the existing file size so a daemon
         * restart doesn't reset the rotation accounting and grow the file
         * past the threshold before noticing. */
        struct stat st;
        if (fstat(fileno(_logFile), &st) == 0) {
            _bytesWritten = (size_t)st.st_size;
        }
    }

    pthread_mutex_unlock(&_logLock);
    return rc;
}

void SGLog_CloseFile(void) {
    pthread_mutex_lock(&_logLock);
    if (_logFile) {
        fflush(_logFile);
        fclose(_logFile);
        _logFile = NULL;
    }
    pthread_mutex_unlock(&_logLock);
}

void SGLog_Flush(void) {
    pthread_mutex_lock(&_logLock);
    if (_logFile) fflush(_logFile);
    pthread_mutex_unlock(&_logLock);
}

void SGLog_Write(SGLogLevel level, const char *tag, const char *fmt, ...) {
    /* Cheap level gate first — no formatting if the line will be dropped. */
    if (level < SGLogLevelError) level = SGLogLevelError;
    if (level > SGLogLevelTrace) level = SGLogLevelTrace;

    pthread_mutex_lock(&_logLock);
    SGLogLevel min = _minLevel;
    pthread_mutex_unlock(&_logLock);
    if (level > min) return;

    /* Body buffer — vsnprintf truncates safely on overflow. */
    char body[1024];
    va_list ap;
    va_start(ap, fmt);
    int bodyLen = vsnprintf(body, sizeof(body), fmt ? fmt : "(null fmt)", ap);
    va_end(ap);
    if (bodyLen < 0) return;
    if ((size_t)bodyLen >= sizeof(body)) bodyLen = (int)sizeof(body) - 1;

    /* Full line: "<ts> <proc>[<pid>] L [tag] body\n" */
    char ts[40];
    SG_FormatTimestamp(ts, sizeof(ts));

    char  line[1200];
    char  levelChar = _levelChars[level];
    const char *safeTag = (tag && tag[0] != '\0') ? tag : "SG";

    int lineLen;
    pthread_mutex_lock(&_logLock);
    if (_procName[0] != '\0') {
        lineLen = snprintf(line, sizeof(line), "%s %s[%d] %c [%s] %s\n",
                           ts, _procName, (int)getpid(), levelChar, safeTag, body);
    } else {
        lineLen = snprintf(line, sizeof(line), "%s [%d] %c [%s] %s\n",
                           ts, (int)getpid(), levelChar, safeTag, body);
    }
    if (lineLen < 0) {
        pthread_mutex_unlock(&_logLock);
        return;
    }
    if ((size_t)lineLen >= sizeof(line)) lineLen = (int)sizeof(line) - 1;

    if (_logFile) {
        fwrite(line, 1, (size_t)lineLen, _logFile);
        _bytesWritten += (size_t)lineLen;

        /* Flush errors and warnings immediately so a crash on the next
         * instruction still leaves a forensic trail.  Info/Debug/Trace
         * ride the stdio buffer for throughput. */
        if (level <= SGLogLevelWarn) fflush(_logFile);

        if (_rotateBytes > 0 && _bytesWritten >= _rotateBytes) {
            SG_RotateLocked();
        }
    }
    pthread_mutex_unlock(&_logLock);

    /* Mirror Error/Warn/Info to syslog so Console.app and the system log
     * stream still catch the important stuff even if the file backend is
     * unavailable.  Debug/Trace are file-only by design. */
    int prio = _syslogPriorities[level];
    if (prio >= 0) {
        /* syslog itself is thread-safe; no need to hold _logLock for this. */
        syslog(prio, "[%s] %s", safeTag, body);
    }
}
