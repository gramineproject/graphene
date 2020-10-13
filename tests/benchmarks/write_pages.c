/*
 * write a number of pages to /dev/null
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    void *buf;
    size_t pagesize;
    ssize_t r;
    int fd, i, ret;

    ret = 1;

    pagesize = sysconf(_SC_PAGESIZE);

    buf = mmap(NULL, pagesize, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        perror("mmap");
        goto err_return;
    }

    memset(buf, 0xa5, pagesize);

    fd = open("/dev/null", O_WRONLY);
    if (fd < 0) {
        perror("open");
        goto err_unmap;
    }

    for (i = 0; i < PAGECOUNT; i++) {
        r = write(fd, buf, pagesize);
        if (r < 0) {
            perror("write");
            goto err_close;
        }
    }

    ret = 0;

err_close:
    close(fd);
err_unmap:
    munmap(buf, pagesize);
err_return:
    return ret;
}
