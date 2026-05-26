#ifndef SKYGLOW_SG_LOG_H
#define SKYGLOW_SG_LOG_H

#include <stddef.h>
#include "SGLogDiagnostics.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SGLog — leveled, file-backed logger for the Skyglow daemon.
 *
 *   All entry points are safe to call from any thread.  A single
 *   pthread_mutex serialises both the level read and the write so that
 *   interleaved lines from multiple threads do not tear.  The lock is held
 *   only across the vsnprintf + fwrite — log calls are not async, but the
 *   write is small and fast (<256 bytes typical).
 *
 * Output format (one line per call):
 *   2026-05-22 14:03:21.482 skyglowd[423] E [SGDaemon] message text
 */

typedef enum {
    SGLogLevelError = 0,
    SGLogLevelWarn  = 1,
    SGLogLevelInfo  = 2,
    SGLogLevelDebug = 3,
    SGLogLevelTrace = 4,
} SGLogLevel;

/**
 * Core write entry point.  Safe to call from any thread, from C or ObjC.
 * `tag` should be a short component name (e.g. "SGDaemon", "SGP").
 * Lines exceeding ~1024 bytes after formatting are truncated.
 *
 * The printf format attribute is checked by the compiler at every call site.
 */
void SGLog_Write(SGLogLevel level, const char *tag, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/**
 * Structured diagnostic entry point.  The formatted body is prefixed with
 * `code=<stable-code>` so support logs are searchable without changing the
 * existing line prefix consumed by Settings.
 */
void SGLog_WriteDiagnostic(SGLogLevel level, const char *tag, const char *code,
                           const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

/**
 * Minimum level that will be emitted.  Calls below this threshold are
 * dropped before formatting, so passing Trace-level data has no cost when
 * the runtime level is Info.  Default is SGLogLevelInfo.
 *
 * Compile-time gating of Debug/Trace happens via the SGLOGD/SGLOGT macros
 * below — this runtime gate exists so a release build can be bumped to
 * Debug from prefs without a rebuild (when DEBUG is defined).
 */
void SGLog_SetMinLevel(SGLogLevel level);
SGLogLevel SGLog_GetMinLevel(void);

/**
 * Open a file-backed sink.  Pass the rotation threshold in bytes — when
 * the file grows past it, it is renamed to "<path>.1" (overwriting any
 * previous .1) and a fresh file is opened.  Pass 0 to disable rotation.
 *
 * The file is created with mode 0644 so the preference bundle (running as
 * mobile in Settings.app) can read it for the in-app log viewer.
 *
 * Calling this a second time closes the previous file and opens the new
 * one.  Returns 0 on success, -1 on failure (errno set).  On failure the
 * logger silently falls back to syslog-only mode — callers should still
 * check the return for diagnostics but the process need not abort.
 */
int  SGLog_OpenFile(const char *path, size_t rotateBytes);
void SGLog_CloseFile(void);
void SGLog_Flush(void);

/**
 * Used for the per-process prefix in formatted lines (e.g. "skyglowd").
 * If unset the prefix is omitted.  Limited to 31 chars; longer names are
 * truncated.
 */
void SGLog_SetProcessName(const char *name);

/**
 * Ergonomic macros.  `tag` is a bare identifier — the macro stringifies it
 * so callers write SGLOGE(SGDaemon, "message") not SGLOGE("SGDaemon", ...).
 *
 * Debug and Trace are compiled out in release builds (NDEBUG defined or
 * DEBUG undefined) so verbose call sites have literally zero cost when
 * shipping.  Errors, warnings, and info always compile in.
 */
#define SGLOGE(tag, fmt, ...) SGLog_Write(SGLogLevelError, #tag, fmt, ##__VA_ARGS__)
#define SGLOGW(tag, fmt, ...) SGLog_Write(SGLogLevelWarn,  #tag, fmt, ##__VA_ARGS__)
#define SGLOGI(tag, fmt, ...) SGLog_Write(SGLogLevelInfo,  #tag, fmt, ##__VA_ARGS__)
#define SGLOGE_CODE(tag, code, fmt, ...) SGLog_WriteDiagnostic(SGLogLevelError, #tag, code, fmt, ##__VA_ARGS__)
#define SGLOGW_CODE(tag, code, fmt, ...) SGLog_WriteDiagnostic(SGLogLevelWarn,  #tag, code, fmt, ##__VA_ARGS__)
#define SGLOGI_CODE(tag, code, fmt, ...) SGLog_WriteDiagnostic(SGLogLevelInfo,  #tag, code, fmt, ##__VA_ARGS__)

#if defined(DEBUG) && !defined(NDEBUG)
  #define SGLOGD(tag, fmt, ...) SGLog_Write(SGLogLevelDebug, #tag, fmt, ##__VA_ARGS__)
  #define SGLOGT(tag, fmt, ...) SGLog_Write(SGLogLevelTrace, #tag, fmt, ##__VA_ARGS__)
  #define SGLOGD_CODE(tag, code, fmt, ...) SGLog_WriteDiagnostic(SGLogLevelDebug, #tag, code, fmt, ##__VA_ARGS__)
  #define SGLOGT_CODE(tag, code, fmt, ...) SGLog_WriteDiagnostic(SGLogLevelTrace, #tag, code, fmt, ##__VA_ARGS__)
#else
  #define SGLOGD(tag, fmt, ...) ((void)0)
  #define SGLOGT(tag, fmt, ...) ((void)0)
  #define SGLOGD_CODE(tag, code, fmt, ...) ((void)0)
  #define SGLOGT_CODE(tag, code, fmt, ...) ((void)0)
#endif

#ifdef __cplusplus
}
#endif

#endif /* SKYGLOW_SG_LOG_H */
