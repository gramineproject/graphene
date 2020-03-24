#include <stdio.h>
#include <stdlib.h>

int main(int argc, char const *argv[]) {
    int ret = system("echo hello from system");
    if (ret) {
        /* something went wrong with system() execution */
        return 1;
    }

    return 0;
}
