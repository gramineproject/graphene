#include "api.h"
#include "cpu.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_regression.h"

#define CHECK(x) ({                                                     \
    __typeof__(x) _x = (x);                                             \
    if (_x < 0) {                                                       \
        pal_printf("Error at line %u, pal_errno: %d\n", __LINE__, _x);  \
        DkProcessExit(1);                                               \
    }                                                                   \
    _x;                                                                 \
})

static void wait_for(int* ptr, int val) {
    while (__atomic_load_n(ptr, __ATOMIC_ACQUIRE) != val) {
        CPU_RELAX();
    }
}

static void set(int* ptr, int val) {
    __atomic_store_n(ptr, val, __ATOMIC_RELEASE);
}

static int g_clear_thread_exit = 1;
static int g_ready = 0;

static void thread_func(void* arg) {
    PAL_HANDLE event = (PAL_HANDLE)arg;
    set(&g_ready, 1);
    wait_for(&g_ready, 2);

    if (DkThreadDelayExecution(TIME_US_IN_S) != TIME_US_IN_S) {
        pal_printf("Error: unexpected short sleep\n");
        DkProcessExit(1);
    }

    DkEventSet(event);

    DkThreadExit(&g_clear_thread_exit);
}

int main(void) {
    PAL_HANDLE event = NULL;
    CHECK(DkEventCreate(&event, /*init_signaled=*/true, /*auto_clear=*/true));

    /* Event is already set, should not sleep. */
    CHECK(DkSynchronizationObjectWait(event, NO_TIMEOUT));

    uint64_t start = 0;
    CHECK(DkSystemTimeQuery(&start));
    /* Sleep for one second. */
    int ret = DkSynchronizationObjectWait(event, TIME_US_IN_S);
    if (ret != -PAL_ERROR_TRYAGAIN) {
        CHECK(-1);
    }
    uint64_t end = 0;
    CHECK(DkSystemTimeQuery(&end));

    if (end < start) {
        CHECK(-1);
    }
    if (end - start < TIME_US_IN_S) {
        CHECK(-1);
    }
    if (end - start > TIME_US_IN_S * 3 / 2) {
        CHECK(-1);
    }

    PAL_HANDLE thread = NULL;
    CHECK(DkThreadCreate(thread_func, event, &thread));

    wait_for(&g_ready, 1);
    set(&g_ready, 2);

    CHECK(DkSystemTimeQuery(&start));
    CHECK(DkSynchronizationObjectWait(event, NO_TIMEOUT));
    CHECK(DkSystemTimeQuery(&end));

    if (end < start) {
        CHECK(-1);
    }
    if (end - start < TIME_US_IN_S) {
        CHECK(-1);
    }
    if (end - start > TIME_US_IN_S * 3 / 2) {
        CHECK(-1);
    }

    wait_for(&g_clear_thread_exit, 0);

    pal_printf("TEST OK\n");
    return 0;
}
