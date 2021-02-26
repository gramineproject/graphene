#include <stdatomic.h>
#include <stdbool.h>

#include "pal.h"
#include "pal_debug.h"
#include "pal_error.h"

static PAL_HANDLE event1;
atomic_int timeouts = 0;

static int thread2_run(void* args) {
    pal_printf("Second thread started.\n");
    DkThreadDelayExecution(3000000);

    pal_printf("Sending event...\n");
    DkEventSet(event1);
    pal_printf("End of second thread.\n");
    DkThreadExit(/*clear_child_tid=*/NULL);
    /* UNREACHABLE */
}

int main(void) {
    pal_printf("Started main thread.\n");

    int ret = DkNotificationEventCreate(0, &event1);
    if (ret < 0 || event1 == NULL) {
        pal_printf("DkNotificationEventCreate failed\n");
        return 1;
    }

    PAL_HANDLE thread2 = NULL;
    ret = DkThreadCreate(thread2_run, NULL, &thread2);
    if (ret < 0) {
        pal_printf("DkThreadCreate failed\n");
        return 1;
    }
    uint64_t t_start = 0;
    if (DkSystemTimeQuery(&t_start) < 0) {
        pal_printf("DkSystemTimeQuery failed\n");
        return 1;
    }

    pal_printf("Testing wait with too short timeout...\n");
    ret = DkSynchronizationObjectWait(event1, 1000000);
    if (ret == -PAL_ERROR_TRYAGAIN) {
        timeouts++;
    }
    uint64_t t_wait1 = 0;
    if (DkSystemTimeQuery(&t_wait1) < 0) {
        pal_printf("DkSystemTimeQuery failed\n");
        return 1;
    }
    uint64_t dt_wait1 = t_wait1 - t_start;
    pal_printf("Wait returned after %lu us.\n", dt_wait1);
    pal_printf("Timeout count: %d\n", timeouts);
    if (dt_wait1 > 1000000 && dt_wait1 < 1100000 && timeouts == 1) {
        pal_printf("Wait with too short timeout ok.\n");
    }

    pal_printf("Testing wait with long enough timeout...\n");
    ret = DkSynchronizationObjectWait(event1, 5000000);
    if (ret == -PAL_ERROR_TRYAGAIN) {
        timeouts++;
    }
    uint64_t t_wait2 = 0;
    if (DkSystemTimeQuery(&t_wait2) < 0) {
        pal_printf("DkSystemTimeQuery failed\n");
        return 1;
    }
    uint64_t dt_wait2 = t_wait2 - t_start;
    pal_printf("Wait returned after %lu us since start.\n", dt_wait2);
    pal_printf("Timeout count: %d\n", timeouts);
    if (dt_wait2 > 3000000 && dt_wait2 < 3100000 && timeouts == 1) {
        pal_printf("Wait with long enough timeout ok.\n");
    }

    pal_printf("End of main thread.\n");
    return 0;
}
