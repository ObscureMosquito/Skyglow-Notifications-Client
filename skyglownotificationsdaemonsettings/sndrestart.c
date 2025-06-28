#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main() {

    if (setuid(0) != 0) {
        perror("Failed to elevate privileges");
        return 1;
    }

    printf("[sndrestart] Restarting Skyglow Notifications Daemon\n");
    system("launchctl unload /Library/LaunchDaemons/com.skyglow.snd.plist");
    system("launchctl load /Library/LaunchDaemons/com.skyglow.snd.plist");
    return 0;
}