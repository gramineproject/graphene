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
struct atomic_int {
    volatile int counter;
};
static struct atomic_int my_counter;

static inline void atomic_inc(struct atomic_int* v) {
    __asm__ __volatile__("lock; incl %0" : "+m"(v->counter));
}

static inline int atomic_read(const struct atomic_int* v)
{
    int i = *(volatile int*)&v->counter;
    return i;
}

static inline void atomic_set(struct atomic_int* v, int i)
{
    v->counter = i;
}

static int futex(int* uaddr, int futex_op, int val, const struct timespec* timeout, int* uaddr2,
                 int val3) {
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr, val3);
}

void* thread_function(void* argument) {
    int* ptr = (int*)argument;
    int rv;
    atomic_inc(&my_counter);

    // Sleep on the futex
    rv = futex(&myfutex, FUTEX_WAIT_BITSET, 0, NULL, NULL, *ptr);
    assert(rv == 0);
    // printf("child thread %d awakened\n", getpid());
    return NULL;
}

int main(int argc, const char** argv) {
    pthread_t thread[THREADS];
    static int varx[THREADS];
    atomic_set(&my_counter, 0);

    for (int i = 0; i < THREADS; i++) {
        varx[i] = (1 << i);

        int ret = pthread_create(&thread[i], NULL, &thread_function, &varx[i]);
        if (ret) {
            errno = ret;
            perror("pthread_create");
            _exit(2);
        }
    }

    // Make sure the threads are sleeping
    do {
        sleep(1);
    } while (atomic_read(&my_counter) != THREADS);
    // one more sleep to mitigate a race between atomic_inc() and futex()
    // in thread_function()
    sleep(1);

    printf("Waking up kiddos\n");
    /* Wake in reverse order */
    for (int i = THREADS - 1; i >= 0; i--) {
        int rv;
        int var = (1 << i);

        // Wake up the thread
        do {
            rv = futex(&myfutex, FUTEX_WAKE_BITSET, 1, NULL, NULL, var);
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
