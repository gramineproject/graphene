#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define TESTFILE "testfile"

int main(int argc, char** argv) {
    int ret = 0, fd;

    if ((ret = creat(TESTFILE, 0600)) < 0) {
        perror("creat");
        exit(1);
    }

    fd = ret;

    if ((ret = write(fd, "Hello World", 11)) < 0) {
        perror("write");
        exit(1);
    }

    close(fd);

    if ((ret = rename(TESTFILE, TESTFILE ".new")) < 0) {
        perror("rename");
        exit(1);
    }

    if ((ret = open(TESTFILE ".new", O_RDONLY)) < 0) {
        perror("open");
        exit(1);
    }

    fd = ret;

    char buffer[12];

    if ((ret = read(fd, buffer, 11)) < 0) {
        perror("read");
        exit(1);
    }

    buffer[11] = 0;
    printf("%s\n", buffer);

    close(fd);

    if ((ret = unlink(TESTFILE ".new")) < 0) {
        perror("unlink");
        exit(1);
    }

    return 0;
}
