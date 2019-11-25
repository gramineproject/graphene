#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char** argv)
{
    int fd = open("/sys/devices/pci0000:00/0000:00:01.1/0000:02:00.0/fpga/intel-fpga-dev.0/device/device", O_RDONLY);
    if (fd < 0) {
            perror("open");
            return 1;
    }

    void* mem = mmap(NULL, 4096, PROT_READ, MAP_SHARED|MAP_FILE,
                     fd, 0);

    if (mem != (void*)-1) {
        fprintf(stderr, "mapped /dev/host-random at %p\n", mem);
    } else {
        perror("mmap");
    }

    char data[16] = {'\0'};
    if (read(fd, data, 16) < 0) {
        perror("file read");
        return 1;
    }
   fprintf(stderr, "data = %s\n", data);
    return 0;
}

