#import "SGLog.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <asl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

static pthread_mutex_t _logLock = PTHREAD_MUTEX_INITIALIZER;

static volatile SGLogLevel _minLevel = SGLogLevelInfo;
static FILE      *_logFile         = NULL;
static char       _logPath[1024]   = {0};
static size_t     _rotateBytes     = 0;
static size_t     _bytesWritten    = 0;
static char       _procName[32]    = {0};
static aslclient  _aslClient       = NULL;
static volatile int _syslogEnabled = 1;

static const char _levelChars[] = { 'E', 'W', 'I', 'D', 'T' };

static const int _aslLevels[] = {
    ASL_LEVEL_ERR,      /* Error */
    ASL_LEVEL_WARNING,  /* Warn  */
    ASL_LEVEL_NOTICE,   /* Info — NOTICE is the default ASL filter cutoff */
    -1,                 /* Debug — file only */
    -1,                 /* Trace — file only */
};

static void SG_RotateLocked(void) {
    if (!_logFile || _rotateBytes == 0 || _logPath[0] == '\0') return;

    fflush(_logFile);
    fclose(_logFile);
    _logFile = NULL;

    char rotated[1024];
    if ((size_t)snprintf(rotated, sizeof(rotated), "%s.1", _logPath) >= sizeof(rotated)) {
        return;
    }
    (void)rename(_logPath, rotated);

    _logFile = fopen(_logPath, "a");
    if (_logFile) {
        (void)fchmod(fileno(_logFile), 0644);
        _bytesWritten = 0;
    }
}

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
    _minLevel = level;
}

SGLogLevel SGLog_GetMinLevel(void) {
    return _minLevel;
}

void SGLog_SetSyslogEnabled(int enabled) {
    _syslogEnabled = enabled ? 1 : 0;
}

void SGLog_SetProcessName(const char *name) {
    pthread_mutex_lock(&_logLock);
    if (name && name[0] != '\0') {
        strncpy(_procName, name, sizeof(_procName) - 1);
        _procName[sizeof(_procName) - 1] = '\0';
        if (!_aslClient) {
            _aslClient = asl_open(_procName, "com.skyglow.daemon", ASL_OPT_NO_DELAY);
            asl_set_filter(_aslClient, ASL_FILTER_MASK_UPTO(ASL_LEVEL_DEBUG));
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
    if (level < SGLogLevelError) level = SGLogLevelError;
    if (level > SGLogLevelTrace) level = SGLogLevelTrace;
    if (level > _minLevel) return;

    char body[1024];
    va_list ap;
    va_start(ap, fmt);
    int bodyLen = vsnprintf(body, sizeof(body), fmt ? fmt : "(null fmt)", ap);
    va_end(ap);
    if (bodyLen < 0) return;
    if ((size_t)bodyLen >= sizeof(body)) bodyLen = (int)sizeof(body) - 1;

    char ts[40];
    SG_FormatTimestamp(ts, sizeof(ts));

    char line[1200];
    char levelChar = _levelChars[level];
    const char *safeTag = (tag && tag[0] != '\0') ? tag : "SG";

    pthread_mutex_lock(&_logLock);

    int lineLen;
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
        fflush(_logFile);

        if (_rotateBytes > 0 && _bytesWritten >= _rotateBytes) {
            SG_RotateLocked();
        }
    }
    pthread_mutex_unlock(&_logLock);

    if (_syslogEnabled) {
        int aslLevel = _aslLevels[level];
        if (aslLevel >= 0) {
            asl_log(_aslClient, NULL, aslLevel, "[%s] %s", safeTag, body);
        }
    }
}
