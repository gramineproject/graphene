#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define TESTDIR "testdir"

int main(int argc, char** argv) {
    int ret = 0;

    if ((ret = rmdir(TESTDIR)) < 0 && errno != ENOENT) {
        perror("rmdir");
        exit(1);
    }

    if ((ret = mkdir(TESTDIR, 0700)) < 0) {
        perror("mkdir");
        exit(1);
    }

    if ((ret = creat(TESTDIR "/file", 0600)) < 0) {
        perror("open");
        exit(1);
    }

    if ((ret = unlink(TESTDIR "/file")) < 0) {
        perror("unlink");
        exit(1);
    }

    if ((ret = rmdir(TESTDIR)) < 0) {
        perror("mkdir");
        exit(1);
    }

    return 0;
}
