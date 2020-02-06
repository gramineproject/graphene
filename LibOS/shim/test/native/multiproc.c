#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char** argv) {
    int times = 0, i;
    pid_t pid;

    if (argc > 1)
        times = atoi(argv[1]);

    for (i = 0; i < times; i++) {
        pid = fork();

        if (pid < 0)
            exit(1);

        if (pid > 0) {
            waitpid(pid, NULL, 0);
            exit(0);
        }
    }

    sleep(1);
    return 0;
}
