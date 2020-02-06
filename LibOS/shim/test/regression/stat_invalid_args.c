#define _XOPEN_SOURCE 700
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char** argv) {
    int r;
    struct stat buf;

    char* goodpath = argv[0];
    char* badpath  = (void*)-1;

    struct stat* goodbuf = &buf;
    struct stat* badbuf  = (void*)-1;

    /* check stat() */
    r = stat(badpath, goodbuf);
    if (r == -1 && errno == EFAULT)
        printf("stat(invalid-path-ptr) correctly returned error\n");

    r = stat(goodpath, badbuf);
    if (r == -1 && errno == EFAULT)
        printf("stat(invalid-buf-ptr) correctly returned error\n");

    /* check lstat() */
    r = lstat(badpath, goodbuf);
    if (r == -1 && errno == EFAULT)
        printf("lstat(invalid-path-ptr) correctly returned error\n");

    r = lstat(goodpath, badbuf);
    if (r == -1 && errno == EFAULT)
        printf("lstat(invalid-buf-ptr) correctly returned error\n");

    return 0;
}
