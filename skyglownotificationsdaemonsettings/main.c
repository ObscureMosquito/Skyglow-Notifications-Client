#include <stdio.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>

extern char **environ;

static int run_cmd(const char *path, char *const argv[]) {
    pid_t pid = 0;
    int status = posix_spawn(&pid, path, NULL, NULL, argv, environ);
    if (status != 0) return status;

    int wstatus = 0;
    if (waitpid(pid, &wstatus, 0) == -1) return 127;
    return (WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : 128);
}

int main(void) {
    if (setuid(0) != 0) {
        perror("Failed to elevate privileges");
        return 1;
    }

    printf("[sndrestart] Restarting Skyglow Notifications Daemon\n");

    // Rootless prefix if present
    const char *plist = "/Library/LaunchDaemons/com.skyglow.snd.plist";
    if (access("/var/jb/Library/LaunchDaemons/com.skyglow.snd.plist", F_OK) == 0) {
        plist = "/var/jb/Library/LaunchDaemons/com.skyglow.snd.plist";
    }

    // Prefer bootstrapctl if available
    const char *ctl = "/var/jb/usr/bin/bootstrapctl";
    if (access(ctl, X_OK) != 0) ctl = "/usr/bin/bootstrapctl";
    if (access(ctl, X_OK) != 0) ctl = "/var/jb/bin/bootstrapctl";
    if (access(ctl, X_OK) != 0) ctl = NULL;

    if (ctl) {
        char *const unload_argv[] = { (char *)ctl, "unload", (char *)plist, NULL };
        char *const load_argv[]   = { (char *)ctl, "load",   (char *)plist, NULL };
        run_cmd(unload_argv[0], unload_argv);
        run_cmd(load_argv[0], load_argv);
        return 0;
    }

    // Fallback to launchctl
    const char *launchctl = "/var/jb/bin/launchctl";
    if (access(launchctl, X_OK) != 0) launchctl = "/bin/launchctl";
    if (access(launchctl, X_OK) != 0) launchctl = "/usr/bin/launchctl";

    char *const unload_argv[] = { (char *)launchctl, "unload", (char *)plist, NULL };
    char *const load_argv[]   = { (char *)launchctl, "load",   (char *)plist, NULL };
    run_cmd(unload_argv[0], unload_argv);
    run_cmd(load_argv[0], load_argv);

    return 0;
}