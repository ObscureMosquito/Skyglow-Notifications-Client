#ifndef SKYGLOW_SG_COMPATIBILITY_SHIM_H
#define SKYGLOW_SG_COMPATIBILITY_SHIM_H

/**
 * Cross-version compatibility shim that fills gaps where the iOS 7 SDK build
 * chain emits code that depends on runtime support introduced in later
 * iOS releases than our deployment floor.
 */

#if defined(__OBJC__)
void SGNInstallCompatibilityShim(void);
#else
extern void SGNInstallCompatibilityShim(void);
#endif

#endif
