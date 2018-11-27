#include <stdio.h>
#include <errno.h>

int main(int argc, char ** argv) {
    errno = EINVAL;
    printf("errno = %d\n", errno);
    return 0;
}
