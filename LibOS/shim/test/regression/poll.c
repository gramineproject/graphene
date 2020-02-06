#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    int ret;
    int fd[2];
    char string[] = "Hello, world!\n";

    ret = pipe(fd);
    if (ret < 0) {
        perror("pipe creation failed");
        return 1;
    }

    struct pollfd outfds[] = {
        {.fd = fd[1], .events = POLLOUT},
    };
    ret = poll(outfds, 1, -1);
    if (ret <= 0) {
        perror("poll with POLLOUT failed");
        return 1;
    }
    printf("poll(POLLOUT) returned %d file descriptors\n", ret);

    struct pollfd infds[] = {
        {.fd = fd[0], .events = POLLIN},
    };
    size_t len = strlen(string) + 1;
    if (write(fd[1], string, len) != len) {
        perror("write error");
        return 1;
    }
    ret = poll(infds, 1, -1);
    if (ret <= 0) {
        perror("poll with POLLIN failed");
        return 1;
    }
    printf("poll(POLLIN) returned %d file descriptors\n", ret);

    return 0;
}
