#include <stdatomic.h>

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

static void pal_failure_handler(PAL_NUM error, PAL_CONTEXT* context) {
    pal_printf("pal_failure_handler called\n");

    if (error == PAL_ERROR_TRYAGAIN) {
        pal_printf("Timeout event received.\n");
        timeouts += 1;
    }
}

int main(void) {
    pal_printf("Started main thread.\n");

    DkSetExceptionHandler(pal_failure_handler, PAL_EVENT_FAILURE);

    event1 = DkNotificationEventCreate(0);
    if (event1 == NULL) {
        pal_printf("DkNotificationEventCreate failed\n");
        return 1;
    }

    PAL_HANDLE thread2 = DkThreadCreate(thread2_run, NULL);
    if (thread2 == NULL) {
        pal_printf("DkThreadCreate failed\n");
        return 1;
    }
    uint64_t t_start = DkSystemTimeQuery();

    pal_printf("Testing wait with too short timeout...\n");
    DkSynchronizationObjectWait(event1, 1000000);
    uint64_t t_wait1  = DkSystemTimeQuery();
    uint64_t dt_wait1 = t_wait1 - t_start;
    pal_printf("Wait returned after %lu us.\n", dt_wait1);
    pal_printf("Timeout count: %d\n", timeouts);
    if (dt_wait1 > 1000000 && dt_wait1 < 1100000 && timeouts == 1) {
        pal_printf("Wait with too short timeout ok.\n");
    }

    pal_printf("Testing wait with long enough timeout...\n");
    DkSynchronizationObjectWait(event1, 5000000);
    uint64_t t_wait2  = DkSystemTimeQuery();
    uint64_t dt_wait2 = t_wait2 - t_start;
    pal_printf("Wait returned after %lu us since start.\n", dt_wait2);
    pal_printf("Timeout count: %d\n", timeouts);
    if (dt_wait2 > 3000000 && dt_wait2 < 3100000 && timeouts == 1) {
        pal_printf("Wait with long enough timeout ok.\n");
    }

    pal_printf("End of main thread.\n");
    return 0;
}
