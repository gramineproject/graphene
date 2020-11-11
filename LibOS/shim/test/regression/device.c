#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char* arvg[]) {
    int devfd = open("/dev/kmsg", O_RDONLY);
    if (devfd < 0) {
        perror("/dev/kmsg open");
        return 1;
    }

    char buf[1024];
    ssize_t bytes = read(devfd, buf, sizeof(buf));
    if (bytes < 0) {
        perror("/dev/kmsg read");
        return 1;
    }

    printf("First line of /dev/kmsg: %s", buf);

    int ret = close(devfd);
    if (ret < 0) {
        perror("/dev/kmsg close");
        return 1;
    }

    puts("TEST OK");
    return 0;
}
