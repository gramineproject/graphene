#include <stdio.h>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc <= 0) {
        return 1;
    } else if (argc == 1) {
        return 0;
    }

    puts(argv[1]);
    fflush(stdout);

    argv[1] = argv[0];
    execv(argv[0], &argv[1]);

    /* must never reach this */
    return 1;
}
