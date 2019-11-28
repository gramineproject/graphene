#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char** argv, char** envp) {
    if (argc > 1) {
        puts(argv[1]);
        return 0;
    }
    char* const new_argv[] = {argv[0], "hello from execv process", NULL};
    execv(new_argv[0], new_argv);

    /* must never reach this */
    return 1;
}
