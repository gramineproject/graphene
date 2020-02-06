#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char** argv) {
    int pipes[2];

    if (pipe(pipes) < 0) {
        perror("pipe error");
        return 1;
    }

    int pid1 = fork();

    if (pid1 < 0) {
        printf("fork failed\n");
        return -1;
    }

    if (pid1 == 0) {
        close(pipes[0]);
        if (write(pipes[1], "hello world", 12) != 12) {
            perror("write error");
            return 1;
        }
        return 0;
    }

    char buffer[20];
    int bytes;

    close(pipes[1]);
    bytes         = read(pipes[0], buffer, 12);
    buffer[bytes] = 0;
    printf("%s\n", buffer);

    waitpid(pid1, NULL, 0);

    return 0;
}
