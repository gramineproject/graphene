#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char** argv) {
    int ret;
    char string[] = "Hello, world!\n";

    /* type 1: pipe */
    int pipefd[2];
    ret = pipe(pipefd);
    if (ret < 0) {
        perror("pipe creation failed");
        return 1;
    }
    /* write something into write end of pipe so read end becomes pollable */
    ret = write(pipefd[1], string, (strlen(string) + 1));
    if (ret < 0) {
        perror("pipe write failed");
        return 1;
    }

    /* type 2: regular file */
    int filefd = open(argv[0], O_RDONLY);
    if (filefd < 0) {
        perror("file open failed");
        return 1;
    }

    /* type 3: dev file */
    int devfd = open("/dev/urandom", O_RDONLY);
    if (devfd < 0) {
        perror("dev/urandom open failed");
        return 1;
    }

    struct pollfd infds[] = {
        {.fd = pipefd[0], .events = POLLIN},
        {.fd = filefd,    .events = POLLIN},
        {.fd = devfd,     .events = POLLIN},
    };

    ret = poll(infds, 3, -1);
    if (ret <= 0) {
        perror("poll with POLLIN failed");
        return 1;
    }
    printf("poll(POLLIN) returned %d file descriptors\n", ret);

    return 0;
}
