#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char** argv) {
    int i;
    for (i=0; i < 1000000; i++) {
        int fd = open("/proc/meminfo", O_RDONLY);
        if (fd == -1) abort();
        close(fd);
    }

    printf("Success\n");

    return 0;
}
