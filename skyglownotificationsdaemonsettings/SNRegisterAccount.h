#import <dns_sd.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#import <Foundation/Foundation.h>

NSString* RegisterAccount(NSString *server_address);