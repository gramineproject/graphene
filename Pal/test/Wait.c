#include "pal.h"
#include "pal_debug.h"

PAL_HANDLE event1;
PAL_HANDLE event2;

int thread1_func(void* args) {
    pal_printf("Enter thread 1\n");

    DkThreadDelayExecution(3000);
    DkEventSet(event1);

    pal_printf("Leave thread 1\n");
    return 0;
}

int thread2_func(void* args) {
    pal_printf("Enter thread 2\n");

    DkThreadDelayExecution(5000);
    DkEventSet(event2);

    pal_printf("Leave thread 2\n");
    return 0;
}

int main(int argc, char** argv) {
    pal_printf("Enter Main Thread\n");

    PAL_HANDLE thd1;
    PAL_HANDLE thd2;

    event1 = DkNotificationEventCreate(0);
    event2 = DkNotificationEventCreate(0);

    thd1 = DkThreadCreate(&thread1_func, 0);
    if (!thd1) {
        pal_printf("DkThreadCreate failed\n");
        return -1;
    }

    thd2 = DkThreadCreate(&thread2_func, 0);
    if (!thd2) {
        pal_printf("DkThreadCreate failed\n");
        return -1;
    }

    PAL_HANDLE hdls[2] = {event1, event2};
    PAL_FLG events[2]  = {PAL_WAIT_READ, PAL_WAIT_READ};
    PAL_FLG revents[2] = {0, 0};

    PAL_BOL polled = DkStreamsWaitEvents(2, hdls, events, revents, NO_TIMEOUT);
    if (!polled) {
        pal_printf("DkStreamsWaitEvents did not return any events\n");
        return -1;
    }

    for (int i = 0; i < 2; i++) {
        if (revents[i])
            pal_printf("event%d is set\n", i + 1);
    }

    pal_printf("Leave main thread\n");
    return 0;
}
