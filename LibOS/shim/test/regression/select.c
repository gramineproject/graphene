#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/types.h>
#include <unistd.h>
#include <unistd.h>

int main(void) {
    fd_set rfds;
    fd_set wfds;

    int  ret;
    int  fd[2];
    char string[] = "Hello, world!\n";
    struct timeval tv = {.tv_sec = 10, .tv_usec = 0};

    pipe(fd);

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_SET(fd[0], &rfds);
    FD_SET(fd[1], &wfds);

    ret = select(fd[1] + 1, NULL, &wfds, NULL, &tv);
    if (ret <= 0) {
        perror("select() on write event failed");
        return 1;
    }
    printf("select() on write event returned %d file descriptors\n", ret);

    write(fd[1], string, (strlen(string)+1));
    ret = select(fd[1] + 1, &rfds, NULL, NULL, &tv);
    if (ret <= 0) {
        perror("select() on read event failed");
        return 1;
    }
    printf("select() on read event returned %d file descriptors\n", ret);

    return 0;
}
