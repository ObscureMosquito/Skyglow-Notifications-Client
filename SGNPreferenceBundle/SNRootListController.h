#import <Preferences/PSListController.h>
#import <UIKit/UIKit.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>

extern char **environ;

@interface SNRootListController : PSListController {
    UIAlertView *alertView;
    UIActivityIndicatorView *activityIndicatorView;
}

/** Posts a Darwin notification to restart the daemon. */
- (void)reloadDaemon;

/** Pushes the debug/diagnostics view controller. */
- (void)pushDebugView;

@end
