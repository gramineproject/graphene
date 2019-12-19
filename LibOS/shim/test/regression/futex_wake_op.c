#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h> 
#include <unistd.h>


static int futex(int* uaddr, int futex_op, int val, const struct timespec* timeout, int* uaddr2, int val3) {
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

static int futex_wait(int* uaddr, int val, const struct timespec* timeout) {
    return futex(uaddr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, val, timeout, NULL, 0);
}

static int futex_wake(int* uaddr, int to_wake) {
    return futex(uaddr, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, to_wake, NULL, NULL, 0);
}

static int futex_wake_op(int* uaddr1, int to_wake1, int* uaddr2, int to_wake2, int op) {
    return futex(uaddr1, FUTEX_WAKE_OP | FUTEX_PRIVATE_FLAG, to_wake1, (struct timespec*)(unsigned long)to_wake2, uaddr2, op);
}

static void fail(const char* msg, int x) {
    printf("%s failed with %d (%s)\n", msg, x, strerror(x));
    exit(1);
}

static void check(int x) {
    if (x) {
        fail("pthread", x);
    }
}

static void store(int* ptr, int val) {
    __atomic_store_n(ptr, val, __ATOMIC_SEQ_CST);
}
static int load(int* ptr) {
    return __atomic_load_n(ptr, __ATOMIC_SEQ_CST);
}

static int wakeop_arg_extend(int x) {
    if (x >= 0x800) {
        return 0xfffff000 | x;
    }
    return x;
}

static int futex1 = 0;
static int futex2 = 0;

#define THREADS1 4
#define THREADS2 5
#define THREADS_WAKE1 2
#define THREADS_WAKE2 3

static int thread_state[THREADS1 + THREADS2] = { 0 };

static void* thread_func(void* arg) {
    unsigned long i = (unsigned long)arg;
    int ret = -1;

    store(&thread_state[i], 1);

    if (i < THREADS1) {
        ret = futex_wait(&futex1, futex1, NULL);
    } else {
        ret = futex_wait(&futex2, futex2, NULL);
    }
    if (ret != 0) {
        printf("futex_wait in thread %lu returned %d (%s)\n", i, ret, strerror(ret));
        // skip setting state below
        return arg;
    }

    store(&thread_state[i], 2);
    return arg;
}

int main(void) {
    pthread_t th[THREADS1 + THREADS2];
    unsigned long i;
    int ret;
    int arg1 = 0x123846;
    int arg2 = 0xc73;
    int cmparg = 0x746; // so that arg1 >= cmparg
    int op = FUTEX_OP(FUTEX_OP_XOR, arg2, FUTEX_OP_CMP_GE, cmparg);

    store(&futex2, arg1);

    for (i = 0; i < THREADS1 + THREADS2; i++) {
        check(pthread_create(&th[i], NULL, thread_func, (void*)i));
    }

    // wait for all threads
    for (i = 0; i < THREADS1 + THREADS2; i++) {
        while (load(&thread_state[i]) != 1) {
            usleep(1000u);
        }
    }
    // and let them sleep on futex
    usleep(100000u);

    ret = futex_wake_op(&futex1, THREADS_WAKE1, &futex2, THREADS_WAKE2, op);

    arg2 = wakeop_arg_extend(arg2);

    op = load(&futex2);
    if (op != (arg1 ^ arg2)) {
        printf("futex_wake_op did not set futex2 value correctly: current value: 0x%x, expected: 0x%x\n", op, arg1 ^ arg2);
        return 1;
    }

    if (ret < 0) {
        fail("futex_wake_op", errno);
    }
    if (ret != THREADS_WAKE1 + THREADS_WAKE2) {
        printf("futex_wake_op returned %d instead of %d!\n", ret, THREADS_WAKE1 + THREADS_WAKE2);
        return 1;
    }

    // let the woken thread(s) end
    usleep(100000u);

    ret = 0;
    for (i = 0; i < THREADS1; i++) {
        if (load(&thread_state[i]) == 2) {
            ret++;
            check(pthread_join(th[i], NULL));
            store(&thread_state[i], 3);
        }
    }
    if (ret != THREADS_WAKE1) {
        printf("futex_wake_op woke-up %d threads on futex1 instead of %d!\n", ret, THREADS_WAKE1);
        return 1;
    }

    ret = 0;
    for (i = THREADS1; i < THREADS1 + THREADS2; i++) {
        if (load(&thread_state[i]) == 2) {
            ret++;
            check(pthread_join(th[i], NULL));
            store(&thread_state[i], 3);
        }
    }
    if (ret != THREADS_WAKE2) {
        printf("futex_wake_op woke-up %d threads on futex2 instead of %d!\n", ret, THREADS_WAKE2);
        return 1;
    }

    ret = futex_wake(&futex1, INT_MAX);
    if (ret < 0) {
        fail("futex_wake(&futex1)", errno);
    }
    if (ret != (THREADS1 - THREADS_WAKE1)) {
        printf("futex_wake on futex1 woke-up %d threads instead of %d!\n", ret, THREADS1 - THREADS_WAKE1);
        return 1;
    }

    ret = futex_wake(&futex2, INT_MAX);
    if (ret < 0) {
        fail("futex_wake(&futex2)", errno);
    }
    if (ret != (THREADS2 - THREADS_WAKE2)) {
        printf("futex_wake on futex2 woke-up %d threads instead of %d!\n", ret, THREADS2 - THREADS_WAKE2);
        return 1;
    }

    for (i = 0; i < THREADS1 + THREADS2; i++) {
        if (load(&thread_state[i]) != 3) {
            check(pthread_join(th[i], NULL));
        }
    }

    puts("Test successful!");
    return 0;
}
