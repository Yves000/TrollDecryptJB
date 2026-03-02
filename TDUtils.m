#import "TDUtils.h"
#import "TDDumpDecrypted.h"
#import "TDCDHash.h"
#import "LSApplicationProxy+AltList.h"
#import <sys/wait.h>

// ptrace declarations (not in public iOS SDK headers)
#define PT_ATTACH    10
#define PT_DETACH    11
int ptrace(int request, pid_t pid, caddr_t addr, int data);

NSString *getLogPath(void) {
    return [NSTemporaryDirectory() stringByAppendingPathComponent:@"lldb_output.log"];
}

static BOOL waitForContentOfFileSync(NSString *filePath, NSString *content, NSTimeInterval timeout) {
    int fd = open([filePath UTF8String], O_EVTONLY);
    if (fd == -1) {
        NSLog(@"[trolldecrypt] Failed to open file for monitoring: %@", filePath);
        return NO;
    }

    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_VNODE, fd, DISPATCH_VNODE_WRITE, queue);
    dispatch_source_set_event_handler(source, ^{
        NSString *fileContent = [NSString stringWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:nil];
        if ([fileContent containsString:content]) {
            NSLog(@"[trolldecrypt] File content matched: %@", filePath);
            dispatch_semaphore_signal(semaphore);
        }
    });
    dispatch_resume(source);

    int rc = dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC)));
    dispatch_source_cancel(source);
    close(fd);

    return (rc == 0);
}


static NSString *lldbQuotedProcessName(const char *executableName) {
    if (!executableName) {
        return nil;
    }
    NSString *name = [NSString stringWithUTF8String:executableName];
    if (!name) {
        return nil;
    }

    NSCharacterSet *controlSet = [NSCharacterSet controlCharacterSet];
    NSMutableString *sanitized = [NSMutableString stringWithCapacity:name.length];
    for (NSUInteger i = 0; i < name.length; i++) {
        unichar c = [name characterAtIndex:i];
        if ([controlSet characterIsMember:c]) {
            continue;
        }
        [sanitized appendFormat:@"%C", c];
    }

    NSString *escaped = [[sanitized stringByReplacingOccurrencesOfString:@"\\" withString:@"\\\\"]
                         stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];
    return [NSString stringWithFormat:@"\"%@\"", escaped];
}

// Global pipe write fd for sending commands to lldb's stdin
static int g_lldb_stdin_fd = -1;

UIWindow *alertWindow = NULL;
UIWindow *kw = NULL;
UIViewController *root = NULL;
UIAlertController *alertController = NULL;
UIAlertController *doneController = NULL;
UIAlertController *errorController = NULL;

NSArray *appList(void) {
    NSMutableArray *apps = [NSMutableArray array];

    NSArray <LSApplicationProxy *> *installedApplications = [[LSApplicationWorkspace defaultWorkspace] atl_allInstalledApplications];
    [installedApplications enumerateObjectsUsingBlock:^(LSApplicationProxy *proxy, NSUInteger idx, BOOL *stop) {
        if (![proxy atl_isUserApplication]) return;

        NSString *bundleID = [proxy atl_bundleIdentifier];
        NSString *name = [proxy atl_nameToDisplay];
        NSString *version = [proxy atl_shortVersionString];
        NSString *executable = proxy.canonicalExecutablePath;

        if (!bundleID || !name || !version || !executable) return;

        NSDictionary *item = @{
            @"bundleID":bundleID,
            @"name":name,
            @"version":version,
            @"executable":executable
        };

        [apps addObject:item];
    }];

    NSSortDescriptor *descriptor = [[NSSortDescriptor alloc] initWithKey:@"name" ascending:YES selector:@selector(localizedCaseInsensitiveCompare:)];
    [apps sortUsingDescriptors:@[descriptor]];

    [apps addObject:@{@"bundleID":@"", @"name":@"", @"version":@"", @"executable":@""}];

    return [apps copy];
}

NSUInteger iconFormat(void) {
    return (UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPad) ? 8 : 10;
}

NSArray *sysctl_ps(void) {
    NSMutableArray *array = [[NSMutableArray alloc] init];

    int numberOfProcesses = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    pid_t pids[numberOfProcesses];
    bzero(pids, sizeof(pids));
    proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < numberOfProcesses; ++i) {
        if (pids[i] == 0) { continue; }
        char pathBuffer[PROC_PIDPATHINFO_MAXSIZE];
        bzero(pathBuffer, PROC_PIDPATHINFO_MAXSIZE);
        proc_pidpath(pids[i], pathBuffer, sizeof(pathBuffer));

        if (strlen(pathBuffer) > 0) {
            NSString *processID = [[NSString alloc] initWithFormat:@"%d", pids[i]];
            NSString *processName = [[NSString stringWithUTF8String:pathBuffer] lastPathComponent];
            NSDictionary *dict = [[NSDictionary alloc] initWithObjects:[NSArray arrayWithObjects:processID, processName, nil] forKeys:[NSArray arrayWithObjects:@"pid", @"proc_name", nil]];
            
            [array addObject:dict];
        }
    }

    return [array copy];
}

static pid_t fastFindPID(NSString *binaryName, NSTimeInterval timeout) {
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeout];
    while ([[NSDate date] compare:deadline] == NSOrderedAscending) {
        int numberOfProcesses = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
        pid_t pids[numberOfProcesses];
        bzero(pids, sizeof(pids));
        proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
        for (int i = 0; i < numberOfProcesses; ++i) {
            if (pids[i] == 0) continue;
            char pathBuffer[PROC_PIDPATHINFO_MAXSIZE];
            bzero(pathBuffer, PROC_PIDPATHINFO_MAXSIZE);
            proc_pidpath(pids[i], pathBuffer, sizeof(pathBuffer));
            if (strlen(pathBuffer) > 0) {
                NSString *procName = [[NSString stringWithUTF8String:pathBuffer] lastPathComponent];
                if ([procName isEqualToString:binaryName]) {
                    return pids[i];
                }
            }
        }
        usleep(1000);
    }
    return -1;
}

void decryptAppFast(NSDictionary *app) {
    dispatch_async(dispatch_get_main_queue(), ^{
        alertWindow = [[UIWindow alloc] initWithFrame: [UIScreen mainScreen].bounds];
        alertWindow.rootViewController = [UIViewController new];
        alertWindow.windowLevel = UIWindowLevelAlert + 1;
        [alertWindow makeKeyAndVisible];
        kw = alertWindow;
        if([kw respondsToSelector:@selector(topmostPresentedViewController)])
            root = [kw performSelector:@selector(topmostPresentedViewController)];
        else
            root = [kw rootViewController];
        root.modalPresentationStyle = UIModalPresentationFullScreen;
    });
    NSLog(@"[trolldecrypt] decryptAppFast...");
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *bundleID = app[@"bundleID"];
        NSString *name = app[@"name"];
        NSString *version = app[@"version"];
        NSString *executable = app[@"executable"];
        NSString *binaryName = [executable lastPathComponent];
        NSLog(@"[trolldecrypt] [fast] bundleID: %@", bundleID);
        NSLog(@"[trolldecrypt] [fast] binaryName: %@", binaryName);
        NSArray *processes = sysctl_ps();
        for (NSDictionary *process in processes) {
            if ([[process objectForKey:@"proc_name"] isEqualToString:binaryName]) {
                pid_t oldPid = [[process objectForKey:@"pid"] intValue];
                NSLog(@"[trolldecrypt] [fast] killing existing process: %d", oldPid);
                kill(oldPid, SIGKILL);
                usleep(100000);
                break;
            }
        }
        __block pid_t foundPid = -1;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
            NSLog(@"[trolldecrypt] [fast] polling for process...");
            foundPid = fastFindPID(binaryName, 15.0);
            if (foundPid > 0) {
                kill(foundPid, SIGSTOP);
                NSLog(@"[trolldecrypt] [fast] SIGSTOP sent to PID %d", foundPid);
            }
            dispatch_semaphore_signal(sem);
        });
        // Inject CDHashes into trustcache before launching
        NSString *appDir = [executable stringByDeletingLastPathComponent];
        NSLog(@"[trolldecrypt] [fast] Injecting trustcache for: %@", appDir);
        NSUInteger injected = TDInjectTrustcacheForApp(appDir);
        NSLog(@"[trolldecrypt] [fast] Trustcache: injected %lu hashes", (unsigned long)injected);

        usleep(10000);
        NSLog(@"[trolldecrypt] [fast] launching app...");
        [[UIApplication sharedApplication] launchApplicationWithIdentifier:bundleID suspended:YES];
        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 15LL * NSEC_PER_SEC));
        if (foundPid <= 0) {
            NSLog(@"[trolldecrypt] [fast] failed to find PID for: %@", binaryName);
            dispatch_async(dispatch_get_main_queue(), ^{
                errorController = [UIAlertController alertControllerWithTitle:@"Error: -1 (fast)" message:[NSString stringWithFormat:@"Failed to get PID for: %@", binaryName] preferredStyle:UIAlertControllerStyleAlert];
                UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"Ok" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                    [errorController dismissViewControllerAnimated:NO completion:nil];
                    [kw removeFromSuperview];
                    kw.hidden = YES;
                }];
                [errorController addAction:okAction];
                [root presentViewController:errorController animated:YES completion:nil];
            });
            return;
        }
        NSLog(@"[trolldecrypt] [fast] process found at PID %d, attaching lldb by PID...", foundPid);
        // Resume from kernel-suspended state so the process is visible to lldb
        kill(foundPid, SIGCONT);
        usleep(50000); // 50ms settle time

        // Use lldb to attach by PID (sets PT_TRACED, which Dopamine requires for task_for_pid)
        NSString *scriptPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"lldb_attach.txt"];
        NSString *scriptContent = [NSString stringWithFormat:@"process attach --pid %d\n", foundPid];
        [scriptContent writeToFile:scriptPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        NSString *logPath = getLogPath();

        // Create a pipe for lldb's stdin so we can send commands later
        int pipefd[2];
        if (pipe(pipefd) != 0) {
            NSLog(@"[trolldecrypt] [fast] Failed to create pipe for lldb stdin");
            kill(foundPid, SIGKILL);
            return;
        }

        pid_t lldb_pid = 0;
        const char *lldb_path = "/var/jb/usr/bin/lldb";
        const char *args[] = { "lldb", "-s", [scriptPath UTF8String], NULL };

        posix_spawn_file_actions_t actions;
        posix_spawn_file_actions_init(&actions);
        posix_spawn_file_actions_adddup2(&actions, pipefd[0], STDIN_FILENO);
        posix_spawn_file_actions_addclose(&actions, pipefd[1]);
        posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, [logPath UTF8String], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, [logPath UTF8String], O_WRONLY | O_CREAT | O_APPEND, 0644);

        int spawnStatus = posix_spawn(&lldb_pid, lldb_path, &actions, NULL, (char *const *)args, NULL);
        posix_spawn_file_actions_destroy(&actions);

        close(pipefd[0]); // close read end in parent

        if (spawnStatus != 0) {
            NSLog(@"[trolldecrypt] [fast] failed to spawn lldb: %d", spawnStatus);
            close(pipefd[1]);
            kill(foundPid, SIGKILL);
            return;
        }
        g_lldb_stdin_fd = pipefd[1]; // store write end
        NSLog(@"[trolldecrypt] [fast] lldb spawned PID %d (stdin pipe fd: %d), waiting for attach...", lldb_pid, g_lldb_stdin_fd);

        // Wait for lldb to attach (look for "Architecture set to" in log)
        BOOL attached = waitForContentOfFileSync(logPath, @"Architecture set to", 10.0);
        if (!attached) {
            NSLog(@"[trolldecrypt] [fast] lldb failed to attach within timeout");
            NSString *logContent = [NSString stringWithContentsOfFile:logPath encoding:NSUTF8StringEncoding error:nil];
            NSLog(@"[trolldecrypt] [fast] lldb log: %@", logContent);
            kill(lldb_pid, SIGKILL);
            kill(foundPid, SIGKILL);
            dispatch_async(dispatch_get_main_queue(), ^{
                errorController = [UIAlertController alertControllerWithTitle:@"Error (fast)" message:@"lldb failed to attach by PID" preferredStyle:UIAlertControllerStyleAlert];
                UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"Ok" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                    [errorController dismissViewControllerAnimated:NO completion:nil];
                    [kw removeFromSuperview];
                    kw.hidden = YES;
                }];
                [errorController addAction:okAction];
                [root presentViewController:errorController animated:YES completion:nil];
            });
            return;
        }
        NSLog(@"[trolldecrypt] [fast] lldb attached! Decrypting PID %d...", foundPid);
        bfinject_rocknroll(foundPid, name, version, lldb_pid);
        kill(foundPid, SIGKILL);
    });
}

void decryptApp(NSDictionary *app) {
    dispatch_async(dispatch_get_main_queue(), ^{
        alertWindow = [[UIWindow alloc] initWithFrame: [UIScreen mainScreen].bounds];
        alertWindow.rootViewController = [UIViewController new];
        alertWindow.windowLevel = UIWindowLevelAlert + 1;
        [alertWindow makeKeyAndVisible];
        
        // Show a "Decrypting!" alert on the device and block the UI
            
        kw = alertWindow;
        if([kw respondsToSelector:@selector(topmostPresentedViewController)])
            root = [kw performSelector:@selector(topmostPresentedViewController)];
        else
            root = [kw rootViewController];
        root.modalPresentationStyle = UIModalPresentationFullScreen;
    });

    NSLog(@"[trolldecrypt] decrypt...");

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{

        NSString *bundleID = app[@"bundleID"];
        NSString *name = app[@"name"];
        NSString *version = app[@"version"];
        NSString *executable = app[@"executable"];
        NSString *binaryName = [executable lastPathComponent];

        NSLog(@"[trolldecrypt] bundleID: %@", bundleID);
        NSLog(@"[trolldecrypt] name: %@", name);
        NSLog(@"[trolldecrypt] version: %@", version);
        NSLog(@"[trolldecrypt] executable: %@", executable);
        NSLog(@"[trolldecrypt] binaryName: %@", binaryName);

        // Inject CDHashes into trustcache before launching
        // (needed for visionOS apps whose signatures aren't trusted by iOS AMFI)
        NSString *appDir = [executable stringByDeletingLastPathComponent];
        NSLog(@"[trolldecrypt] Injecting trustcache for: %@", appDir);
        NSUInteger injected = TDInjectTrustcacheForApp(appDir);
        NSLog(@"[trolldecrypt] Trustcache: injected %lu hashes", (unsigned long)injected);

        NSLog(@"[trolldecrypt] lldb --waitfor for '%@'...", binaryName);
        pid_t lldb_pid = attachLLDBToProcessByName([binaryName UTF8String], -1);//-1 for unknown
        
        if (lldb_pid <= 0) {
            dispatch_async(dispatch_get_main_queue(), ^{
                errorController = [UIAlertController alertControllerWithTitle:@"Error: lldb" message:@"Failed to start lldb. Make sure lldb is installed." preferredStyle:UIAlertControllerStyleAlert];
                UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"Ok" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                    [errorController dismissViewControllerAnimated:NO completion:nil];
                    [kw removeFromSuperview];
                    kw.hidden = YES;
                }];
                [errorController addAction:okAction];
                [root presentViewController:errorController animated:YES completion:nil];
            });
            return;
        }
        
        // Kill existing process if any
        NSArray *processes;
        NSLog(@"[trolldecrypt] kill existing process if any...");
        processes = sysctl_ps();
        for (NSDictionary *process in processes) {
            NSString *proc_name = process[@"proc_name"];
            if ([proc_name isEqualToString:binaryName]) {
                pid_t pid = [process[@"pid"] intValue];
                NSLog(@"[trolldecrypt] Found app PID: %d (existing)", pid);
                kill(pid, SIGKILL);
                break;
            }
        }
        
        NSLog(@"[trolldecrypt] launch app and lldb force pause...");
        [[UIApplication sharedApplication] launchApplicationWithIdentifier:bundleID suspended:YES]; // Launch app in suspended state
        waitForContentOfFileSync(getLogPath(), @"Architecture set to", 30.0); // Wait for lldb to attach
        
        // Get PID after lldb caught it
        pid_t pid = -1;
        processes = sysctl_ps();
        for (NSDictionary *process in processes) {
            NSString *proc_name = process[@"proc_name"];
            if ([proc_name isEqualToString:binaryName]) {
                pid = [process[@"pid"] intValue];
                NSLog(@"[trolldecrypt] Found app PID: %d (paused by lldb)", pid);
                break;
            }
        }

        if (pid == -1) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [alertController dismissViewControllerAnimated:NO completion:nil];
                NSLog(@"[trolldecrypt] failed to get pid for binary name: %@", binaryName);

                errorController = [UIAlertController alertControllerWithTitle:@"Error: -1" message:[NSString stringWithFormat:@"Failed to get PID for binary name: %@", binaryName] preferredStyle:UIAlertControllerStyleAlert];
                UIAlertAction *okAction = [UIAlertAction actionWithTitle:NSLocalizedString(@"Ok", @"Ok") style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                    NSLog(@"[trolldecrypt] Ok action");
                    [errorController dismissViewControllerAnimated:NO completion:nil];
                    [kw removeFromSuperview];
                    kw.hidden = YES;
                }];

                [errorController addAction:okAction];
                [root presentViewController:errorController animated:YES completion:nil];
            });

            return;
        }

        NSLog(@"[trolldecrypt] pid: %d", pid);

        bfinject_rocknroll(pid, name, version, lldb_pid);
    });
}

pid_t attachLLDBToProcessByName(const char *executableName, pid_t target_pid) {
    NSLog(@"[trolldecrypt] Attaching lldb to executable: %s (PID: %d)", executableName, target_pid);
    NSString *scriptPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"lldb_attach.txt"];
    NSString *quotedName = lldbQuotedProcessName(executableName);
    if (!quotedName) {
        NSLog(@"[trolldecrypt] Invalid executable name for lldb attach");
        return 0;
    }
    NSString *scriptContent = [NSString stringWithFormat:
        @"process attach --name %@ --waitfor\n", quotedName];
    [scriptContent writeToFile:scriptPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    NSString *logPath = getLogPath();

    // Create a pipe for lldb's stdin so we can send commands later
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        NSLog(@"[trolldecrypt] Failed to create pipe for lldb stdin");
        return 0;
    }

    pid_t lldb_pid = 0;
    const char *lldb_path = "/var/jb/usr/bin/lldb";
    const char *args[] = {
        "lldb",
        "-s", [scriptPath UTF8String],
        NULL
    };

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);

    // Redirect stdin to read end of pipe
    posix_spawn_file_actions_adddup2(&actions, pipefd[0], STDIN_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipefd[1]); // close write end in child
    posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, [logPath UTF8String], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, [logPath UTF8String], O_WRONLY | O_CREAT | O_APPEND, 0644);

    int status = posix_spawn(&lldb_pid, lldb_path, &actions, NULL, (char *const *)args, NULL);
    posix_spawn_file_actions_destroy(&actions);

    close(pipefd[0]); // close read end in parent

    if (status == 0) {
        g_lldb_stdin_fd = pipefd[1]; // store write end for later use
        NSLog(@"[trolldecrypt] lldb spawned done, lldb PID: %d (stdin pipe fd: %d)", lldb_pid, g_lldb_stdin_fd);
        NSLog(@"[trolldecrypt] lldb output: %@", logPath);

        waitForContentOfFileSync(logPath, @"process attach --name", 5.0);
        sleep(1);

        if (kill(lldb_pid, 0) == 0) {
            NSLog(@"[trolldecrypt] lldb attached to '%s' (PID: %d)", executableName, target_pid);
        } else {
            NSLog(@"[trolldecrypt] lldb process died");
            lldb_pid = 0;
            close(pipefd[1]);
            g_lldb_stdin_fd = -1;
        }
    } else {
        NSLog(@"[trolldecrypt] fail to spawn lldb: %d", status);
        lldb_pid = 0;
        close(pipefd[1]);
        g_lldb_stdin_fd = -1;
    }

    return lldb_pid;
}

int getLLDBStdinFd(void) {
    return g_lldb_stdin_fd;
}

// Detach lldb from process
void detachLLDB(pid_t lldb_pid) {
    if (lldb_pid > 0) {
        NSLog(@"[trolldecrypt] Detaching lldb (PID: %d)", lldb_pid);

        kill(lldb_pid, SIGTERM);
        
        sleep(1);
      
        if (kill(lldb_pid, 0) == 0) {
            NSLog(@"[trolldecrypt] lldb still running, sending SIGKILL");
            kill(lldb_pid, SIGKILL);
        }
        
        NSLog(@"[trolldecrypt] lldb detached successfully");

        // Reap the lldb process
        int unused;
        waitpid(lldb_pid, &unused, WNOHANG);
    }
}

void bfinject_rocknroll(pid_t pid, NSString *appName, NSString *version, pid_t lldb_pid) {
    NSLog(@"[trolldecrypt] decrypt...");
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{;
        NSLog(@"[trolldecrypt] Process PID: %d, lldb PID: %d", pid, lldb_pid);

		// Get full path
		char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
        proc_pidpath(pid, pathbuf, sizeof(pathbuf));
		const char *fullPathStr = pathbuf;

        NSLog(@"[trolldecrypt] fullPathStr: %s", fullPathStr);
        NSLog(@"[trolldecrypt] Process is already PAUSED by lldb");
        
        DumpDecrypted *dd = [[DumpDecrypted alloc] initWithPathToBinary:[NSString stringWithUTF8String:fullPathStr] appName:appName appVersion:version];
        if(!dd) {
            NSLog(@"[trolldecrypt] ERROR: failed to get DumpDecrypted instance");
            return;
        }

        NSLog(@"[trolldecrypt] Full path to app: %s   ///   IPA File: %@", fullPathStr, [dd IPAPath]);

        dispatch_async(dispatch_get_main_queue(), ^{
            alertWindow = [[UIWindow alloc] initWithFrame: [UIScreen mainScreen].bounds];
            alertWindow.rootViewController = [UIViewController new];
            alertWindow.windowLevel = UIWindowLevelAlert + 1;
            [alertWindow makeKeyAndVisible];
            
            // Show a "Decrypting!" alert on the device and block the UI
            alertController = [UIAlertController
                alertControllerWithTitle:@"Decrypting"
                message:@"Please wait, this will take a few seconds..."
                preferredStyle:UIAlertControllerStyleAlert];
                
            kw = alertWindow;
            if([kw respondsToSelector:@selector(topmostPresentedViewController)])
                root = [kw performSelector:@selector(topmostPresentedViewController)];
            else
                root = [kw rootViewController];
            root.modalPresentationStyle = UIModalPresentationFullScreen;
            [root presentViewController:alertController animated:YES completion:nil];
        });
        
        NSLog(@"[trolldecrypt] Starting decryption while process is paused...");

        // Try task_for_pid first, fall back to LLDB-based decryption
        // jbctl proc_set_debugged to allow task_for_pid
        {
            char pidStr[16];
            snprintf(pidStr, sizeof(pidStr), "%d", pid);
            pid_t jbctl_pid;
            char *argv[] = {"/var/jb/basebin/jbctl", "proc_set_debugged", pidStr, NULL};
            posix_spawn(&jbctl_pid, "/var/jb/basebin/jbctl", NULL, NULL, argv, NULL);
            int st;
            waitpid(jbctl_pid, &st, 0);
            NSLog(@"[trolldecrypt] jbctl proc_set_debugged %d result: %d", pid, WEXITSTATUS(st));
        }

        vm_map_t testTask = 0;
        kern_return_t kr = task_for_pid(mach_task_self(), pid, &testTask);
        if (kr == KERN_SUCCESS) {
            NSLog(@"[trolldecrypt] task_for_pid succeeded");

            // Resume the process briefly to let dyld initialize and FairPlay decrypt.
            // When caught by lldb, the process is stopped before dyld runs,
            // so the dyld image list is empty (0 images). We need to let it run
            // so dyld loads the binary (triggering FairPlay page decryption).
            // The process will crash on framework loading (wrong platform),
            // and lldb will catch the crash signal, keeping pages in memory.
            int lldb_fd = getLLDBStdinFd();
            if (lldb_fd >= 0) {
                NSLog(@"[trolldecrypt] Resuming process via lldb to let dyld initialize...");
                const char *cmd = "continue\n";
                write(lldb_fd, cmd, strlen(cmd));

                // Wait for dyld to load and crash (should be < 1 second)
                sleep(3);

                // Ensure the process is stopped
                const char *intCmd = "process interrupt\n";
                write(lldb_fd, intCmd, strlen(intCmd));
                usleep(500000);

                NSLog(@"[trolldecrypt] Process should now have dyld initialized, reading memory...");
            } else {
                NSLog(@"[trolldecrypt] WARNING: No lldb stdin pipe, trying direct read (dyld may not be initialized)");
            }

            [dd createIPAFile:pid];
        } else {
            NSLog(@"[trolldecrypt] task_for_pid failed (%d), using LLDB-based decryption", kr);
            [dd createIPAFileViaLLDB:pid lldbPID:lldb_pid];
        }
        NSLog(@"[trolldecrypt] Decryption complete!");

        NSLog(@"[trolldecrypt] Detaching lldb...");
        detachLLDB(lldb_pid);

        // Dismiss the alert box
        dispatch_async(dispatch_get_main_queue(), ^{
            [alertController dismissViewControllerAnimated:NO completion:nil];

            doneController = [UIAlertController alertControllerWithTitle:@"Decryption Complete!" message:[NSString stringWithFormat:@"IPA file saved to:\n%@\n\nThanks to lldb so we can archive this!", [dd IPAPath]] preferredStyle:UIAlertControllerStyleAlert];

            UIAlertAction *okAction = [UIAlertAction actionWithTitle:NSLocalizedString(@"Ok", @"Ok") style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                [kw removeFromSuperview];
                kw.hidden = YES;
            }];
            [doneController addAction:okAction];

            if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"filza://"]]) {
                UIAlertAction *openAction = [UIAlertAction actionWithTitle:@"Show in Filza" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                    [kw removeFromSuperview];
                    kw.hidden = YES;

                    NSString *urlString = [NSString stringWithFormat:@"filza://view%@", [dd IPAPath]];
                    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:urlString] options:@{} completionHandler:nil];
                }];
                [doneController addAction:openAction];
            }

            [root presentViewController:doneController animated:YES completion:nil];
        }); // dispatch on main
                    
        NSLog(@"[trolldecrypt] Over and out.");
    }); // dispatch in background
    
    NSLog(@"[trolldecrypt] All done.");
}

NSArray *decryptedFileList(void) {
    NSMutableArray *files = [NSMutableArray array];
    NSMutableArray *fileNames = [NSMutableArray array];

    // iterate through all files in the Documents directory
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSDirectoryEnumerator *directoryEnumerator = [fileManager enumeratorAtPath:docPath()];

    NSString *file;
    while (file = [directoryEnumerator nextObject]) {
        if ([[file pathExtension] isEqualToString:@"ipa"]) {
            NSString *filePath = [[docPath() stringByAppendingPathComponent:file] stringByStandardizingPath];

            NSDictionary *fileAttributes = [fileManager attributesOfItemAtPath:filePath error:nil];
            NSDate *modificationDate = fileAttributes[NSFileModificationDate];

            NSDictionary *fileInfo = @{@"fileName": file, @"modificationDate": modificationDate};
            [files addObject:fileInfo];
        }
    }

    // Sort the array based on modification date
    NSArray *sortedFiles = [files sortedArrayUsingComparator:^NSComparisonResult(id obj1, id obj2) {
        NSDate *date1 = [obj1 objectForKey:@"modificationDate"];
        NSDate *date2 = [obj2 objectForKey:@"modificationDate"];
        return [date2 compare:date1];
    }];

    // Get the file names from the sorted array
    for (NSDictionary *fileInfo in sortedFiles) {
        [fileNames addObject:[fileInfo objectForKey:@"fileName"]];
    }

    return [fileNames copy];
}

NSString *docPath(void) {
    NSError * error = nil;
    [[NSFileManager defaultManager] createDirectoryAtPath:@"/var/mobile/Documents/TrollDecrypt/decrypted" withIntermediateDirectories:YES attributes:nil error:&error];
    if (error != nil) {
        NSLog(@"[trolldecrypt] error creating directory: %@", error);
    }

    return @"/var/mobile/Documents/TrollDecrypt/decrypted";
}

void decryptAppWithPID(pid_t pid) {
    // generate App NSDictionary object to pass into decryptApp()
    // proc_pidpath(self.pid, buffer, sizeof(buffer));
    NSString *message = nil;
    NSString *error = nil;

    dispatch_async(dispatch_get_main_queue(), ^{
        alertWindow = [[UIWindow alloc] initWithFrame: [UIScreen mainScreen].bounds];
        alertWindow.rootViewController = [UIViewController new];
        alertWindow.windowLevel = UIWindowLevelAlert + 1;
        [alertWindow makeKeyAndVisible];
        
        // Show a "Decrypting!" alert on the device and block the UI
            
        kw = alertWindow;
        if([kw respondsToSelector:@selector(topmostPresentedViewController)])
            root = [kw performSelector:@selector(topmostPresentedViewController)];
        else
            root = [kw rootViewController];
        root.modalPresentationStyle = UIModalPresentationFullScreen;
    });

    NSLog(@"[trolldecrypt] pid: %d", pid);

    char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
    proc_pidpath(pid, pathbuf, sizeof(pathbuf));

    NSString *executable = [NSString stringWithUTF8String:pathbuf];
    NSString *path = [executable stringByDeletingLastPathComponent];
    NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:[path stringByAppendingPathComponent:@"Info.plist"]];
    NSString *bundleID = infoPlist[@"CFBundleIdentifier"];

    if (!bundleID) {
        error = @"Error: -2";
        message = [NSString stringWithFormat:@"Failed to get bundle id for pid: %d", pid];
    }

    LSApplicationProxy *app = [LSApplicationProxy applicationProxyForIdentifier:bundleID];
    if (!app) {
        error = @"Error: -3";
        message = [NSString stringWithFormat:@"Failed to get LSApplicationProxy for bundle id: %@", bundleID];
    }

    if (message) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [alertController dismissViewControllerAnimated:NO completion:nil];
            NSLog(@"[trolldecrypt] failed to get bundleid for pid: %d", pid);

            errorController = [UIAlertController alertControllerWithTitle:error message:message preferredStyle:UIAlertControllerStyleAlert];
            UIAlertAction *okAction = [UIAlertAction actionWithTitle:NSLocalizedString(@"Ok", @"Ok") style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                NSLog(@"[trolldecrypt] Ok action");
                [errorController dismissViewControllerAnimated:NO completion:nil];
                [kw removeFromSuperview];
                kw.hidden = YES;
            }];

            [errorController addAction:okAction];
            [root presentViewController:errorController animated:YES completion:nil];
        });
    }

    NSLog(@"[trolldecrypt] app: %@", app);

    NSDictionary *appInfo = @{
        @"bundleID":bundleID,
        @"name":[app atl_nameToDisplay],
        @"version":[app atl_shortVersionString],
        @"executable":executable
    };

    NSLog(@"[trolldecrypt] appInfo: %@", appInfo);

    dispatch_async(dispatch_get_main_queue(), ^{
        [alertController dismissViewControllerAnimated:NO completion:nil];
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Decrypt" message:[NSString stringWithFormat:@"Decrypt %@?", appInfo[@"name"]] preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *cancel = [UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil];
        UIAlertAction *decrypt = [UIAlertAction actionWithTitle:@"Yes" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            decryptApp(appInfo);
        }];

        [alert addAction:decrypt];
        [alert addAction:cancel];
        
        [root presentViewController:alert animated:YES completion:nil];
    });
}

// void github_fetchLatedVersion(NSString *repo, void (^completionHandler)(NSString *latestVersion)) {
//     NSString *urlString = [NSString stringWithFormat:@"https://api.github.com/repos/%@/releases/latest", repo];
//     NSURL *url = [NSURL URLWithString:urlString];

//     NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
//         if (!error) {
//             if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
//                 NSError *jsonError;
//                 NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];

//                 if (!jsonError) {
//                     NSString *version = [json[@"tag_name"] stringByReplacingOccurrencesOfString:@"v" withString:@""];
//                     completionHandler(version);
//                 }
//             }
//         }
//     }];

//     [task resume];
// }

void fetchLatestTrollDecryptVersion(void (^completionHandler)(NSString *version)) {
    //github_fetchLatedVersion(@"donato-fiore/TrollDecrypt", completionHandler);
}

NSString *trollDecryptVersion(void) {
    return [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleVersion"];
}