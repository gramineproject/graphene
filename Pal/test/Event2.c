#include "pal.h"
#include "pal_debug.h"

static PAL_HANDLE event1;

int count = 0;

int thread_func(void* args) {
    DkThreadDelayExecution(1000);

    pal_printf("In thread 1\n");

    while (count < 100)
        count++;

    DkEventSet(event1);
    DkThreadExit(/*clear_child_tid=*/NULL);
    return 0; /* NOTREACHED */
}

int main(int argc, char** argv) {
    pal_printf("Enter main thread\n");

    PAL_HANDLE thd1;

    event1 = DkNotificationEventCreate(0);
    if (!event1) {
        pal_printf("DkNotificationEventCreate failed\n");
        return -1;
    }

    thd1 = DkThreadCreate(&thread_func, 0);
    if (!thd1) {
        pal_printf("DkThreadCreate failed\n");
        return -1;
    }

    /* wait till thread thd1 is done */
    DkSynchronizationObjectWait(event1, NO_TIMEOUT);

    if (count != 100)
        return -1;

    /* this wait should return immediately */
    DkSynchronizationObjectWait(event1, NO_TIMEOUT);

    pal_printf("Success, leave main thread\n");
    return 0;
}
