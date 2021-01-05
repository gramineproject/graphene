/* test creates two threads simulteneously writing on the same pipe */

#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>

#define ITERATIONS 100000

int fds[2];

static void* thread_run(void* arg) {
    char c = (char)(uintptr_t)arg;
    for (int i = 0; i < ITERATIONS; i++) {
        ssize_t bytes = 0;
        while (bytes < sizeof(c)) {
            bytes = send(fds[1], &c, sizeof(c), /*flags=*/0);
            if (bytes < 0) {
                if (errno == EAGAIN || errno == EINTR)
                    continue;
                err(1, "send");
            }
        }
    }
    return NULL;
}

int main(int argc, char** argv) {
    int ret;
    pthread_t threads[2];
    char thread_ids[2]   = {42, 24};
    int thread_bytes[2]  = {0, 0};

    ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    if (ret) {
        err(1, "socketpair");
    }

    ret = pthread_create(&threads[0], NULL, &thread_run, (void*)(uintptr_t)thread_ids[0]);
    if (ret) {
        errno = ret;
        err(1, "pthread_create");
    }

    ret = pthread_create(&threads[1], NULL, &thread_run, (void*)(uintptr_t)thread_ids[1]);
    if (ret) {
        errno = ret;
        err(1, "pthread_create");
    }

    for (int i = 0; i < 2 * ITERATIONS; i++) {
        char c = 0;
        ssize_t bytes = 0;
        while (bytes < sizeof(c)) {
            bytes = recv(fds[0], &c, sizeof(c), /*flags=*/0);
            if (bytes < 0) {
                if (errno == EAGAIN || errno == EINTR)
                    continue;
                err(1, "recv");
            }
        }

        if (c == thread_ids[0])
            thread_bytes[0] += bytes;
        else if (c == thread_ids[1])
            thread_bytes[1] += bytes;
        else
            errx(1, "received unrecognized thread ID");
    }

    printf("received total bytes from threads: %d and %d\n", thread_bytes[0], thread_bytes[1]);

    if (thread_bytes[0] != ITERATIONS || thread_bytes[1] != ITERATIONS)
        errx(1, "received wrong number of bytes from threads");

    puts("TEST OK");
    return 0;
}
