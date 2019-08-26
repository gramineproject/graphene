#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
    int fd = open("test.open.file", O_CREAT | O_RDWR, S_IRWXU);

    int fd2 = open("fs.manifest", O_RDONLY);

    char* buf = malloc(4096);

    int ret;
    while ((ret = read(fd2, buf, 4096)) > 0) {
        write(1, buf, ret);
        write(fd, buf, ret);
    }

    close(fd);
}
