#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>

#define DEFAULT_PLIST_PATH "/Library/LaunchDaemons/com.skyglow.snd.plist"
#define DEFAULT_LAUNCHCTL_PATH "/bin/launchctl"

extern char **environ;

char plist_path[1024];
char launchctl_path[1024];
char jb_prefix[1024] = "";

void log_msg(int priority, const char *format, ...) {
    va_list args;
    va_start(args, format);
    vsyslog(priority, format, args);
    va_end(args);
    va_start(args, format);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

void setup_paths() {
    struct stat st;
    if (stat("/var/jb", &st) == 0) {
        strcpy(jb_prefix, "/var/jb");
        snprintf(launchctl_path, sizeof(launchctl_path), "/var/jb/bin/launchctl");
        snprintf(plist_path, sizeof(plist_path), "/var/jb/Library/LaunchDaemons/com.skyglow.snd.plist");
    } else {
        strcpy(jb_prefix, "");
        snprintf(launchctl_path, sizeof(launchctl_path), DEFAULT_LAUNCHCTL_PATH);
        snprintf(plist_path, sizeof(plist_path), DEFAULT_PLIST_PATH);
    }
}

int run_launchctl(const char *action) {
    pid_t pid;
    const char *argv[] = {launchctl_path, action, plist_path, NULL};

    log_msg(LOG_NOTICE, "[sndrestart] Executing: %s %s %s", launchctl_path, action, plist_path);

    int spawn_ret = posix_spawn(&pid, launchctl_path, NULL, NULL, (char* const*)argv, environ);
    
    if (spawn_ret == 0) {
        int status;
        if (waitpid(pid, &status, 0) != -1) {
            if (WIFEXITED(status)) {
                int exit_code = WEXITSTATUS(status);
                log_msg(LOG_NOTICE, "[sndrestart] launchctl %s exited with code: %d", action, exit_code);
                return exit_code;
            } else {
                log_msg(LOG_ERR, "[sndrestart] launchctl %s crashed or was killed.", action);
            }
        } else {
            log_msg(LOG_ERR, "[sndrestart] waitpid failed: %s", strerror(errno));
        }
    } else {
        log_msg(LOG_ERR, "[sndrestart] posix_spawn failed: %s", strerror(spawn_ret));
    }
    return -1;
}

int main(int argc, char **argv) {
    openlog("sndrestart", LOG_PID | LOG_CONS, LOG_USER);
    setup_paths();
    
    log_msg(LOG_NOTICE, "--- Starting Skyglow Daemon Restart Tool ---");
    log_msg(LOG_NOTICE, "[sndrestart] Mode: %s", strlen(jb_prefix) > 0 ? "Rootless" : "Rootful");

    if (setuid(0) != 0) {
        log_msg(LOG_ERR, "CRITICAL: Failed to setuid(0). Error: %s", strerror(errno));
        log_msg(LOG_ERR, "Fix: chmod 4755 %s/Library/PreferenceBundles/SGNPreferenceBundle.bundle/sndrestart", jb_prefix);
    } else {
        setgid(0);
        log_msg(LOG_NOTICE, "Root privileges acquired successfully.");
    }

    int unload_ret = run_launchctl("unload");
    
    if (unload_ret != 0) {
        log_msg(LOG_WARNING, "Unload returned non-zero (Daemon likely wasn't running). Proceeding...");
    }

    usleep(500000); 

    int load_ret = run_launchctl("load");

    if (load_ret != 0) {
        log_msg(LOG_ERR, "CRITICAL: Failed to load daemon. Exit code: %d", load_ret);
        closelog();
        return 1;
    }

    log_msg(LOG_NOTICE, "Daemon loaded successfully. Exiting.");
    closelog();
    return 0;
}