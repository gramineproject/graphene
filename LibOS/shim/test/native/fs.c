#define _XOPEN_SOURCE 700
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
        if (write(1, buf, ret) != ret || write(fd, buf, ret) != ret) {
            perror("write error");
            return 1;
        }
    }
    if (ret < 0) {
        perror("read error");
        return 1;
    }

    close(fd);
    return 0;
}
