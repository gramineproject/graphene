#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv, const char** envp) {
    FILE* out = stdout;

    if (argc > 1) {
        int fd = atoi(argv[argc - 1]);
        printf("inherited file descriptor %d\n", fd);
        out = fdopen(fd, "a");
        if (!out) {
            perror("fdopen");
            exit(1);
        }
    }

    fprintf(out, "Hello World (%s)!\n", argv[0]);
    fprintf(out, "envp[\'IN_EXECVE\'] = %s\n", getenv("IN_EXECVE"));
    return 0;
}
