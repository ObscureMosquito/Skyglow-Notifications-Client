#ifndef SKYGLOW_SG_CONTROL_AUTHORIZATION_H
#define SKYGLOW_SG_CONTROL_AUTHORIZATION_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

/**
 * Resolves a Mach request sender's executable identity and applies the
 * control-channel allowlist.
 *
 * The audit-token euid remains authoritative. The path is preferred when the
 * kernel exposes one; the kernel process name is only a compatibility fallback
 * on older iOS versions. Output buffers are always initialized and safe to log.
 */
bool SGControlSenderIsAuthorized(pid_t pid,
                                 uid_t euid,
                                 char *outName,
                                 size_t nameCapacity,
                                 char *outPath,
                                 size_t pathCapacity);

#endif
