#ifndef SKYGLOW_SG_LOG_H
#define SKYGLOW_SG_LOG_H

#include <stddef.h>
#include "SGLogDiagnostics.h"

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

/* Mirror Error/Warn/Info to the system log (ASL on iOS so Console.app sees
 * the daemon as a proper sender with level + tag).  Default ON.  Disable
 * via prefs if the user wants their system log kept clean. */
void SGLog_SetSyslogEnabled(int enabled);

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
