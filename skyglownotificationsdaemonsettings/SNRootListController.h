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

- (void)reloadDaemon;
- (void)showGuide;
- (void)generateSSLCertificate;
- (void)generateKeys;

@end
