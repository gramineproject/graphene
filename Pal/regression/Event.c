#include <stdatomic.h>

#include "pal.h"
#include "pal_debug.h"
#include "pal_error.h"

static PAL_HANDLE event1;
atomic_int timeouts = 0;

int thread2_run(void* args) {
    pal_printf("Second thread started.\n");
    DkThreadDelayExecution(3000000);

    pal_printf("Sending event...\n");
    DkEventSet(event1);
    pal_printf("End of second thread.\n");
    DkThreadExit(/*clear_child_tid=*/NULL);

    return 0;
}

void pal_failure_handler(PAL_PTR event, PAL_NUM error, PAL_CONTEXT* context) {
    pal_printf("pal_failure_handler called\n");

    if (error == PAL_ERROR_TRYAGAIN) {
        pal_printf("Timeout event received.\n");
        timeouts += 1;
    }

    DkExceptionReturn(event);
}

int main() {
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
    unsigned long t_start = DkSystemTimeQuery();

    pal_printf("Testing wait with too short timeout...\n");
    DkSynchronizationObjectWait(event1, 1000000);
    unsigned long t_wait1  = DkSystemTimeQuery();
    unsigned long dt_wait1 = t_wait1 - t_start;
    pal_printf("Wait returned after %lu us.\n", dt_wait1);
    pal_printf("Timeout count: %d\n", timeouts);
    if (dt_wait1 > 1000000 && dt_wait1 < 1100000 && timeouts == 1) {
        pal_printf("Wait with too short timeout ok.\n");
    }

    pal_printf("Testing wait with long enough timeout...\n");
    DkSynchronizationObjectWait(event1, 5000000);
    unsigned long t_wait2  = DkSystemTimeQuery();
    unsigned long dt_wait2 = t_wait2 - t_start;
    pal_printf("Wait returned after %lu us since start.\n", dt_wait2);
    pal_printf("Timeout count: %d\n", timeouts);
    if (dt_wait2 > 3000000 && dt_wait2 < 3100000 && timeouts == 1) {
        pal_printf("Wait with long enough timeout ok.\n");
    }

    pal_printf("End of main thread.\n");
    return 0;
}
