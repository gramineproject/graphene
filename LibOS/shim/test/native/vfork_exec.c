#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, const char** argv, const char** envp) {
    int newfd = dup(1), outfd = dup(1);
    char fd_argv[4];
    snprintf(fd_argv, 4, "%d", newfd);
    char* const new_argv[] = {"./exec_victim", fd_argv, NULL};

    setenv("IN_EXECVE", "1", 1);

    int pid = vfork();
    if (pid == 0) {
        close(outfd);
        execv(new_argv[0], new_argv);
    }

    wait(NULL);

    FILE* out = fdopen(outfd, "a");
    if (!out) {
        printf("cannot open file descriptor\n");
        return -1;
    }

    fprintf(out, "Goodbye world!\n");
    return 0;
}
