#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char** argv) {
    struct dirent* dirent;
    DIR* dir;

    dir = opendir("/proc/1");
    if (!dir) {
        perror("opendir /proc/1");
        exit(1);
    }
    while ((dirent = readdir(dir))) {
        printf("/proc/1/%s\n", dirent->d_name);
    }
    closedir(dir);

    // Children end up inheriting junk if we don't flush here.
    fflush(stdout);

/* This code tickles a bug in exit/wait for PIDs/IPC; created an issue (#532), will revisit after 
 * landing some related IPC fixes that are pending. */
#if 0
    for (int i = 0 ; i < 3 ; i++) {
        pid_t pid = fork();

        if (pid < 0) {
            perror("fork");
            exit(1);
        }

        if (pid) {
            waitpid(pid, NULL, 0);
            exit(0);
        }
    }
#endif

    dir = opendir("/proc");
    if (!dir) {
        perror("opendir /proc");
        exit(1);
    }
    while ((dirent = readdir(dir))) {
        printf("/proc/%s\n", dirent->d_name);
    }
    closedir(dir);

    return 0;
}
