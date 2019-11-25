#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "ioctl-dummy-driver/dummy.h"

int main(int argc, char **argv)
{
    int fd = open("/dev/dummy", O_RDWR);
    if (fd < 0) {
            perror("open");
            return 1;
    }

    for (int i = 1; i < argc; i++) {
        struct dummy_print arg;
        arg.str = argv[i];
        arg.size = strlen(argv[i]);

        if (ioctl(fd, DUMMY_IOCTL_PRINT, &arg)) {
            perror("ioctl");
            return 1;
        }

        fprintf(stderr, "wrote %s to kernel\n", argv[i]);
    }

    void *mem = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FILE,
                     fd, 0);

    if (!mem) {
        perror("mmap");
        return 1;
    }

    fprintf(stderr, "mapped /dev/dummy at %p\n", mem);
    for (int i = 0; i < 4096; i++)
        if (((unsigned char *) mem)[i]) {
            perror("memory read");
            return 1;
        }

    return 0;
}

