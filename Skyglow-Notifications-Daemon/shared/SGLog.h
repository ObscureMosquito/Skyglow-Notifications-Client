#ifndef SKYGLOW_SG_LOG_H
#define SKYGLOW_SG_LOG_H

#include <stddef.h>
#include "SGLogDiagnostics.h"

/* Compile-time sink defaults. Override any of these with -D for a particular
 * build without changing call sites or the daemon's main logic. */
#ifndef SG_LOG_FILE_DEFAULT_ENABLED
#define SG_LOG_FILE_DEFAULT_ENABLED 1
#endif

#ifndef SG_LOG_CONSOLE_DEFAULT_ENABLED
#define SG_LOG_CONSOLE_DEFAULT_ENABLED 1
#endif

#ifndef SG_LOG_TTY_DEFAULT_ENABLED
#define SG_LOG_TTY_DEFAULT_ENABLED 1
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SGLogLevelError = 0,
    SGLogLevelWarn  = 1,
    SGLogLevelInfo  = 2,
    SGLogLevelDebug = 3,
    SGLogLevelTrace = 4,
} SGLogLevel;

void SGLog_Write(SGLogLevel level, const char *tag, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

void SGLog_SetMinLevel(SGLogLevel level);
SGLogLevel SGLog_GetMinLevel(void);

int  SGLog_OpenFile(const char *path, size_t rotateBytes);
void SGLog_CloseFile(void);
void SGLog_Flush(void);

void SGLog_SetProcessName(const char *name);

/* Runtime switches initialized from the compile-time defaults above. */
void SGLog_SetFileEnabled(int enabled);
void SGLog_SetConsoleEnabled(int enabled);
void SGLog_SetTTYEnabled(int enabled);

/* Console uses ASL on legacy systems and Foundation's unified-log path on
 * modern systems. TTY output is additionally guarded by isatty(stdout). */

#define SGLOGE(tag, fmt, ...) SGLog_Write(SGLogLevelError, #tag, fmt, ##__VA_ARGS__)
#define SGLOGW(tag, fmt, ...) SGLog_Write(SGLogLevelWarn,  #tag, fmt, ##__VA_ARGS__)
#define SGLOGI(tag, fmt, ...) SGLog_Write(SGLogLevelInfo,  #tag, fmt, ##__VA_ARGS__)

#if defined(DEBUG) && !defined(NDEBUG)
  #define SGLOGD(tag, fmt, ...) SGLog_Write(SGLogLevelDebug, #tag, fmt, ##__VA_ARGS__)
  #define SGLOGT(tag, fmt, ...) SGLog_Write(SGLogLevelTrace, #tag, fmt, ##__VA_ARGS__)
#else
  #define SGLOGD(tag, fmt, ...) ((void)0)
  #define SGLOGT(tag, fmt, ...) ((void)0)
#endif

#ifdef __cplusplus
}
#endif

#endif
