#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <poll.h>

int main(void) {
    int  ret;
    int  fd[2];
    char string[] = "Hello, world!\n";

    pipe(fd);

    struct pollfd outfds[] = { {.fd = fd[1], .events = POLLOUT}, };
    ret = poll(outfds, 1, -1);
    if (ret <= 0) {
        perror("poll with POLLOUT failed");
        return 1;
    }
    printf("poll(POLLOUT) returned %d file descriptors\n", ret);

    struct pollfd infds[] = { {.fd = fd[0], .events = POLLIN}, };
    write(fd[1], string, (strlen(string)+1));
    ret = poll(infds, 1, -1);
    if (ret <= 0) {
        perror("poll with POLLIN failed");
        return 2;
    }
    printf("poll(POLLIN) returned %d file descriptors\n", ret);

    return 0;
}


