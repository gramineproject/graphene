#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, const char** argv, const char** envp) {
    pid_t child_pid;

    char c = 0;
    ssize_t x = read(0, &c, 1);
    if (x < 0) {
        err(1, "stdin read failed");
    } else if (x != 1) {
        assert(x == 0);
        errx(1, "unexpected eof on stdin");
    }
    assert(c == 'a');
    x = read(0, &c, 1);
    if (x < 0) {
        err(1, "stdin 2nd read failed");
    }
    if (x != 0) {
        errx(1, "stdin read succeeded unexpectedly");
    }

    /* duplicate STDOUT into newfd and pass it as exec_victim argument
     * (it will be inherited by exec_victim) */
    int newfd = dup(1);
    if (newfd < 0) {
        perror("dup failed");
        return 1;
    }

    char fd_argv[12];
    snprintf(fd_argv, 12, "%d", newfd);
    char* const new_argv[] = {"./exec_victim", fd_argv, NULL};

    /* set environment variable to test that it is inherited by exec_victim */
    int ret = setenv("IN_EXECVE", "1", 1);
    if (ret < 0) {
        perror("setenv failed");
        return 1;
    }

    child_pid = fork();

    if (child_pid == 0) {
        /* child performs execve(exec_victim) */
        execv(new_argv[0], new_argv);
        perror("execve failed");
        return 1;
    } else if (child_pid > 0) {
        /* parent waits for child termination */
        int status;
        pid_t pid = wait(&status);
        if (pid < 0) {
            perror("wait failed");
            return 1;
        }
        if (WIFEXITED(status))
            printf("child exited with status: %d\n", WEXITSTATUS(status));
    } else {
        /* error */
        perror("fork failed");
        return 1;
    }

    puts("test completed successfully");
    return 0;
}
