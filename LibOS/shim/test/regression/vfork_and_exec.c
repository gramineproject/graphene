#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, const char** argv, const char** envp) {
    pid_t child_pid;

    /* duplicate STDOUT into newfd and pass it as exec_victim argument
     * (it will be inherited by exec_victim) */
    int newfd = dup(1);
    char fd_argv[4];
    snprintf(fd_argv, 4, "%d", newfd);
    char* const new_argv[] = {"./exec_victim", fd_argv, NULL};

    /* set environment variable to test that it is inherited by exec_victim */
    setenv("IN_EXECVE", "1", 1);

    child_pid = vfork();

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
