#include <stdatomic.h>

#include "pal.h"
#include "pal_debug.h"

volatile bool dummy_true = true;

static atomic_bool thread2_started = false;
static atomic_bool thread3_started = false;
static atomic_bool thread3_exit_ok = true;
static atomic_bool thread4_started = false;

int thread2_run(void* args) {
    pal_printf("Thread 2 started.\n");

    thread2_started = true;

    pal_printf("Exiting thread 2 by return.\n");
    return 0;
}

int thread3_run(void* args) {
    pal_printf("Thread 3 started.\n");

    thread3_started = true;

    pal_printf("Exiting thread 3 by DkThreadExit.\n");

    // Ensure that the compiler can't know that this should never return.
    if (dummy_true) {
        DkThreadExit(/*clear_child_tid=*/NULL);
    }

    thread3_exit_ok = false;
    pal_printf("Exiting thread 3 failed.\n");

    return 0;
}

int thread4_run(void* args) {
    pal_printf("Thread 4 started.\n");

    thread4_started = true;

    pal_printf("Exiting thread 4 by return.\n");
    return 0;
}

// If there's a thread limit, like on SGX, it should be set to exactly 2. There
// should be only the main thread and only one other thread at a time.
int main() {
    pal_printf("Thread 1 (main) started.\n");

    PAL_HANDLE thread2 = DkThreadCreate(thread2_run, NULL);
    if (!thread2) {
        pal_printf("DkThreadCreate failed for thread 2.\n");
        return 1;
    }

    // 1 s should be enough even on a very busy system to start a thread and
    // then exit it again including all cleanup.
    DkThreadDelayExecution(1000000);

    if (thread2_started) {
        pal_printf("Thread 2 ok.\n");
    }

    PAL_HANDLE thread3 = DkThreadCreate(thread3_run, NULL);
    if (!thread3) {
        pal_printf("DkThreadCreate failed for thread 3.\n");
        return 1;
    }

    DkThreadDelayExecution(1000000);

    if (thread3_started && thread3_exit_ok) {
        pal_printf("Thread 3 ok.\n");
    }

    PAL_HANDLE thread4 = DkThreadCreate(thread4_run, NULL);
    if (!thread4) {
        pal_printf("DkThreadCreate failed for thread 4.\n");
        return 1;
    }

    DkThreadDelayExecution(1000000);

    if (thread4_started) {
        pal_printf("Thread 4 ok.\n");
    }

    return 0;
}
