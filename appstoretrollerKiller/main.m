#include <stdio.h>
#import <Foundation/Foundation.h>
#import <spawn.h>
#import <rootless.h>
#import "TSUtil.h"

static void kickstart(const char *service) {
    pid_t pid;
    const char *launchctl = ROOT_PATH("/usr/bin/launchctl");
    char *args[] = {(char *)launchctl, "kickstart", (char *)service, NULL};
    extern char **environ;
    if (posix_spawn(&pid, args[0], NULL, NULL, args, environ) == 0) {
        int status;
        waitpid(pid, &status, 0);
    }
}

int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool {
        if (getuid() == 501) {
            if (argc > 1 && strcmp(argv[1], "--child") == 0) {
                exit(1);
            }

            spawnRoot(ROOT_PATH_NS(@"/usr/local/bin/TDDaemonKiller"), @[ @"", @"--child" ], nil, nil);
            exit(0);
        }
        killall(@"appstored", NO);
        killall(@"installd", YES);
        killall(@"AppStore", YES);

        // Wait for processes to die and cfprefsd to flush
        usleep(500000);

        // Fix plist permissions — NSUserDefaults/cfprefsd writes as 0600,
        // but installd runs as _installd and needs read access
        NSString *prefsPath = ROOT_PATH_NS(@"/var/mobile/Library/Preferences/com.trolldecrypt.hook.plist");
        [[NSFileManager defaultManager] setAttributes:@{NSFilePosixPermissions: @(0644)} ofItemAtPath:prefsPath error:nil];

        // Force-restart on-demand daemons so hooks load immediately
        kickstart("system/com.apple.appstored");
        kickstart("system/com.apple.mobile.installd");
        exit(0);
	}
}
