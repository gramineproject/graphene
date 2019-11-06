#define _GNU_SOURCE
#include <asm/prctl.h>
#include <assert.h>
#include <linux/futex.h>
#include <malloc.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

// 64kB stack
#define FIBER_STACK (1024 * 64)
#define THREADS     2
static int myfutex = 0;

static int futex(int* uaddr, int futex_op, int val, const struct timespec* timeout, int* uaddr2,
                 int val3) {
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr, val3);
}

void* thread_function(void* argument) {
    int* ptr = (int*)argument;
    int rv;

    // Sleep on the futex
    rv = futex(&myfutex, FUTEX_WAIT_BITSET, 0, NULL, NULL, *ptr);
    assert(rv == 0);
    // printf("child thread %d awakened\n", getpid());
    return NULL;
}

int main(int argc, const char** argv) {
    pthread_t thread[THREADS];
    static int varx[THREADS];

    for (int i = 0; i < THREADS; i++) {
        varx[i] = (1 << i);

        int ret = pthread_create(&thread[i], NULL, &thread_function, &varx[i]);
        if (ret) {
            errno = ret;
            perror("pthread_create");
            _exit(2);
        }
    }

    printf("Waking up kiddos\n");
    /* Wake in reverse order */
    for (int i = THREADS - 1; i >= 0; i--) {
        int rv;
        int var = (1 << i);

        // Wake up the thread
        do {
            rv = futex(&myfutex, FUTEX_WAKE_BITSET, 1, NULL, NULL, var);
            if (rv == 0) {
                // the thread of thread_function() may not reach
                // futex(FUTEX_WAIT_BITSET) yet.
                // Wait for the thread to sleep and try again.
                // Since synchronization primitive, futex, is being tested,
                // futex can't be used here. resort to use sleep.
                sleep(1);
            }
        } while (rv == 0);
        printf("FUTEX_WAKE_BITSET i = %d rv = %d\n", i, rv);
        assert(rv == 1);

        // Wait for the child thread to exit
        int ret = pthread_join(thread[i], NULL);
        if (ret) {
            errno = ret;
            perror("pthread_join");
            _exit(3);
        }
    }

    printf("Woke all kiddos\n");

    return 0;
}
