#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char* argv[] = {"./fork", NULL};
    execv(argv[0], argv);
    return 0;
}
