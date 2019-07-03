#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

int main (int argc, char** argv) {
    int r, fd;
    struct stat buf;

    fd = open(".", O_DIRECTORY);
    if (fd == -1) {
        printf("Opening CWD returns error %d\n", errno);
        return -1;
    }

    r = fstat(fd, &buf);
    if (r == -1) {
        printf("fstat on directory fd returns error %d\n", errno);
        return -1;
    }

    close(fd);

    if (S_ISDIR(buf.st_mode))
        printf("fstat returns the fd type as S_IFDIR\n");

    return 0;
}
