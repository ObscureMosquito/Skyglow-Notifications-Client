#import "SNLogViewController.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define SOCKET_PATH "/var/run/lockdown/syslog.sock"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    CGFloat parentWidth = 379; // Width of the parent view or cell
    CGFloat textViewHeight = 154; // Desired height of the textView
    CGFloat textViewWidth = parentWidth * 0.8; // textView width as 80% of the parent view or cell
    
    CGFloat textViewX = -1;
    CGFloat textViewY = -109; // Adjust as needed for vertical placement, ensuring it's a positive value for positioning within the parent view
    
    self.logTextView = [[UITextView alloc] initWithFrame:CGRectMake(textViewX, textViewY, textViewWidth, textViewHeight)];
    self.logTextView.editable = NO;
    self.logTextView.backgroundColor = [UIColor blackColor];
    self.logTextView.textColor = [UIColor whiteColor];
    self.logTextView.layer.cornerRadius = 8; // Rounded corners
    self.logTextView.layer.masksToBounds = YES;
    self.logTextView.layer.borderWidth = 2.0; // Thin border width
    self.logTextView.layer.borderColor = [[UIColor lightGrayColor] CGColor]; // Light gray border color, similar to PSCells
    
    
    [self.view addSubview:self.logTextView];
    
    [self performSelectorInBackground:@selector(startLogStreaming) withObject:nil];
}


- (void)startLogStreaming {
    int nfd = unix_connect(SOCKET_PATH);
    
    if (nfd < 0) {
        NSLog(@"Failed to connect to socket");
        return;
    }
    
    // Write "watch" command to socket to begin receiving messages
    write(nfd, "watch\n", 6);
    
    unsigned char buf[16384];
    ssize_t n;
    
    while (1) {
        n = read(nfd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            NSString *logString = [NSString stringWithUTF8String:(char *)buf];
            
            // Filter to include only logs from SkyglowNotificationsDaemon
            if ([logString rangeOfString:@"SkyglowNotificationsDaemon"].location != NSNotFound ||
            [logString rangeOfString:@"sndrestart"].location != NSNotFound) {
                
                // Filter out "MS:" messages
                if ([logString rangeOfString:@"MS:"].location == NSNotFound) {
                    // Extract log type enclosed in "<>"
                    NSRange startRange = [logString rangeOfString:@"<"];
                    NSRange endRange = [logString rangeOfString:@">"];
                    
                    if (startRange.location != NSNotFound && endRange.location != NSNotFound) {
                        NSRange typeRange = NSMakeRange(startRange.location + 1, endRange.location - startRange.location - 1);
                        NSString *logType = [logString substringWithRange:typeRange];
                        
                        // Format the log message
                        NSString *formattedLog = [NSString stringWithFormat:@"%@%@", logType, [logString substringFromIndex:endRange.location + 1]];
                        
                        dispatch_async(dispatch_get_main_queue(), ^{
                            // Append the formatted log message
                            self.logTextView.text = [self.logTextView.text stringByAppendingFormat:@"\n%@", formattedLog];
                            
                            // Auto-scroll to bottom
                            NSRange range = NSMakeRange(self.logTextView.text.length - 1, 1);
                            [self.logTextView scrollRangeToVisible:range];
                        });
                    }
                }
            }
        } else if (n == 0) {
            break; // Socket closed
        } else if (n < 0) {
            NSLog(@"Read error: %s", strerror(errno));
            break;
        }
    }
    
    close(nfd);
}



int unix_connect(char* path) {
    struct sockaddr_un sun;
    int s;
    
    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
        return (-1);
    
    memset(&sun, 0, sizeof(struct sockaddr_un));
    sun.sun_family = AF_UNIX;
    
    if (strlcpy(sun.sun_path, path, sizeof(sun.sun_path)) >= sizeof(sun.sun_path)) {
        close(s);
        errno = ENAMETOOLONG;
        return (-1);
    }
    if (connect(s, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
        close(s);
        return (-1);
    }
    
    return s;
}

@end
