#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static pid_t gettid(void) {
    return syscall(SYS_gettid);
}

static int tkill(int tid, int sig) {
    return syscall(SYS_tkill, tid, sig);
}

static pid_t who1 = 0;
static pid_t who2 = 0;

static void handler(int signum) {
    pid_t v = 0;
    pid_t my_tid = gettid();
    if (!__atomic_compare_exchange_n(&who1, &v, my_tid, /*weak=*/0,
                                     __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        __atomic_store_n(&who2, my_tid, __ATOMIC_SEQ_CST);
    }
    printf("handler called in: %d\n", my_tid);
}

static int sync_var = 0;

static void set(int x) {
    __atomic_store_n(&sync_var, x, __ATOMIC_SEQ_CST);
}

static void wait_for(int x) {
    while (__atomic_load_n(&sync_var, __ATOMIC_SEQ_CST) != x) {
        __asm__ volatile("pause");
    }
}

static void* f(void* x) {
    printf("thread id: %d\n", gettid());

    struct sigaction action = { 0 };
    action.sa_handler = handler;

    int ret = sigaction(SIGTERM, &action, NULL);
    if (ret < 0) {
        fprintf(stderr, "sigaction failed\n");
        exit(1);
    }

    set(1);
    wait_for(2);

    return x;
}

int main() {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    pthread_t th;

    if (pthread_create(&th, NULL, f, NULL)) {
        fprintf(stderr, "pthread_create failed: %m\n");
        return 1;
    }

    wait_for(1);

    pid_t tid = gettid();

    printf("parent tid: %d\n", tid);

    if (tkill(tid, SIGTERM)) {
        fprintf(stderr, "tkill failed: %m\n");
        return 1;
    }

    set(2);

    if (pthread_join(th, NULL)) {
        fprintf(stderr, "pthread_join failed: %m\n");
        return 1;
    }

    pid_t w1 = __atomic_load_n(&who1, __ATOMIC_SEQ_CST);
    pid_t w2 = __atomic_load_n(&who2, __ATOMIC_SEQ_CST);

    if (w1 != tid || w2 != 0) {
        fprintf(stderr, "test failed: (%d, %d)\n", w1, w2);
        return 1;
    }

    puts("TEST OK!");

    return 0;
}
