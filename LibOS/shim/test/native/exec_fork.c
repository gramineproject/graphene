#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

int main() {
    char * argv[] = { "./fork", NULL };
    execv(argv[0], argv);
    return 0;
}
