#include "skyglownotificationsdaemonsettings/SNRegisterAccount.h"
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "SNRootListController.h"
#import "SNGuideViewController.h"
#import "SNLogViewController.h"

#define kBundlePath @"/Library/PreferenceBundles/SkyglowNotificationsDaemonSettings.bundle"

@implementation SNRootListController

- (NSArray *)specifiers {
	if (!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
	}

	return _specifiers;
}

- (void)reloadDaemon {
    NSLog(@"[Sndrestart] Invoking the binary to restart the daemon");
    
    pid_t pid;
    char *args[] = {"/Library/PreferenceBundles/SkyglowNotificationsDaemonSettings.bundle/sndrestart", NULL};
    int status;
    
    // Spawn the process
    status = posix_spawn(&pid, args[0], NULL, NULL, args, environ);
    
    if (status == 0) {
        NSLog(@"[Sndrestart] Successfully spawned the process.");
        
        // Wait for the spawned process to finish, if necessary
        if (waitpid(pid, &status, 0) == -1) {
            NSLog(@"[Sndrestart] Error waiting for the process to finish.");
        } else {
            NSLog(@"[Sndrestart] Process finished.");
        }
    } else {
        NSLog(@"[Sndrestart] Failed to spawn the process.");
    }
}

- (void)showGuide {
    GuideViewController *guideVC = [[GuideViewController alloc] init];
    [self.navigationController pushViewController:guideVC animated:YES];
}

- (void)registerDevice {
    UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"Registering Device"
                                                    message:@"\n" // Increase the number of line breaks for additional spacing
                                                   delegate:nil
                                          cancelButtonTitle:nil
                                          otherButtonTitles:nil];
    UIActivityIndicatorView *activityView = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhiteLarge];

    // Show the alert first to get its dimensions
    [alert show];

    // Delayed adjustment to attempt to accommodate the alert's dynamic layout
    double delayInSeconds = 0.1;
    dispatch_time_t popTime = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delayInSeconds * NSEC_PER_SEC));
    dispatch_after(popTime, dispatch_get_main_queue(), ^(void){
        // Adjust spinner's frame directly to move it lower and possibly make the alert look "thinner"
        CGRect alertBounds = alert.bounds;
        CGPoint center = CGPointMake(CGRectGetMidX(alertBounds), CGRectGetMidY(alertBounds) + 20); // Adjust the Y offset as needed
        activityView.center = center;
        [alert addSubview:activityView];
        [activityView startAnimating];
    });

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Generate the keys
        NSString *serverAddress = [self getServerAddressFromPreferences];
        NSLog(@"[Skyglow Notifications] Registering with server %@", serverAddress);
        NSString *result = RegisterAccount(serverAddress);
        NSLog(@"[Skyglow Notifications] Registering with server finsished with %@. (null means sucess)", result);

        dispatch_async(dispatch_get_main_queue(), ^{
            // Dismiss the alert
            [alert dismissWithClickedButtonIndex:0 animated:YES];

            if (result) {
                [[[UIAlertView alloc] initWithTitle:@"Failed to Register Device!"
                                                    message:[NSString stringWithFormat:@"An error has occured while trying to register your device. (%@)", result]
                                                   delegate:nil
                                          cancelButtonTitle:@"Okay"
                                          otherButtonTitles:nil] show];
            }
        });
    });
}


- (void)generateKeys {
    NSString *bundlePath = @"/Library/PreferenceBundles/SkyglowNotificationsDaemonSettings.bundle/Keys";

    // Define paths for server keys
    NSString *serverPrivateKeyPath = [bundlePath stringByAppendingPathComponent:@"server_private_key.pem"];
    NSString *serverPublicKeyPath = [bundlePath stringByAppendingPathComponent:@"public_key.pem"];

    // Define paths for client keys
    NSString *clientPrivateKeyPath = [bundlePath stringByAppendingPathComponent:@"private_key.pem"];
    NSString *clientPublicKeyPath = [bundlePath stringByAppendingPathComponent:@"client_public_key.pem"];

    // Function to generate key pair
    void (^generateKeyPair)(NSString *, NSString *) = ^(NSString *privateKeyPath, NSString *publicKeyPath) {
        RSA *rsa = RSA_new();
        BIGNUM *bn = BN_new();
        BN_set_word(bn, RSA_F4); // RSA_F4 is a common public exponent

        if (RSA_generate_key_ex(rsa, 2048, bn, NULL) != 1) {
            // Handle key generation error
            NSLog(@"Failed to generate RSA key");
            RSA_free(rsa);
            BN_free(bn);
            return;
        }

        // Save private key
        FILE *privateKeyFile = fopen([privateKeyPath UTF8String], "w");
        if (!privateKeyFile || PEM_write_RSAPrivateKey(privateKeyFile, rsa, NULL, NULL, 0, NULL, NULL) != 1) {
            // Handle error
            NSLog(@"Failed to write private key");
        }
        if (privateKeyFile) fclose(privateKeyFile);

        // Save public key in X.509 SubjectPublicKeyInfo format
        FILE *publicKeyFile = fopen([publicKeyPath UTF8String], "w");
        if (!publicKeyFile || PEM_write_RSA_PUBKEY(publicKeyFile, rsa) != 1) {
            // Handle error
            NSLog(@"Failed to write public key");
        }
        if (publicKeyFile) fclose(publicKeyFile);

        RSA_free(rsa);
        BN_free(bn);
    };

    // Generate server key pair
    generateKeyPair(serverPrivateKeyPath, serverPublicKeyPath);

    // Generate client key pair
    generateKeyPair(clientPrivateKeyPath, clientPublicKeyPath);
}

- (NSString *)getServerAddressFromPreferences {
    // how u do dis? im just gonna hard code it for now
    return @"test.preloading.dev";
}

@end
