#ifndef SKYGLOW_SG_COMPATIBILITY_SHIM_H
#define SKYGLOW_SG_COMPATIBILITY_SHIM_H

/** Backfills runtime symbols the iOS 7 SDK expects but older iOS lacks. */

#if defined(__OBJC__)
void SGNInstallCompatibilityShim(void);
#else
extern void SGNInstallCompatibilityShim(void);
#endif

#endif
