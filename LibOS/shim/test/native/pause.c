#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void handler(int signal) {
    printf("hello world\n");
}

int main(int argc, char** argv) {
    if (signal(SIGALRM, &handler) < 0)
        return EXIT_FAILURE;

    if (alarm(1) < 0)
        return EXIT_FAILURE;

    int ret = pause();
    assert(ret == -1);
    assert(errno == EINTR);

    printf("good bye\n");
    return 0;
}
