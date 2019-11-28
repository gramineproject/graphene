#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, const char** argv, const char** envp) {
    if (argc > 1) {
        puts(argv[1]);
        return 0;
    }
    char* const new_argv[] = {"./exec_same", "hello from execv process", NULL};
    execv(new_argv[0], new_argv);

    /* must never reach this */
    return 1;
}
