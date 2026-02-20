#ifndef SKYGLOW_GLOBALS_H
#define SKYGLOW_GLOBALS_H

#import "DBManager.h"
#import <Foundation/Foundation.h>

/// The server address string from the registration profile.
/// e.g. @"sgn.example.com". Set once in main() before threads start.
extern NSString *serverAddress;

/// Shared database instance. Initialized in main() before threads start.
extern DBManager *db;

/// Resolved server IP string (e.g. @"93.184.216.34").
/// Set once in main() after DNS resolution. Read by connectionLoop.
/// Must not be modified after the connection loop thread starts.
extern NSString *serverIPString;

/// Resolved server port string (e.g. @"4443").
/// Same lifecycle as serverIPString.
extern NSString *serverPortString;

// serverIP (char *) and serverPortStr (char *) have been removed.
// Use serverIPString and serverPortString (NSString *) instead.

#endif /* SKYGLOW_GLOBALS_H */