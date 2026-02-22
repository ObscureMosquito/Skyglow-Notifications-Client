#ifndef SKYGLOW_GLOBALS_H
#define SKYGLOW_GLOBALS_H

#import "DBManager.h"
#import <Foundation/Foundation.h>

/// Shared database instance.
extern DBManager *db;

// --- Thread-Safe Configuration Accessors ---

void SetServerAddress(NSString *address);
NSString *GetServerAddress(void);

void SetServerIPString(NSString *ip);
NSString *GetServerIPString(void);

void SetServerPortString(NSString *port);
NSString *GetServerPortString(void);

#endif /* SKYGLOW_GLOBALS_H */