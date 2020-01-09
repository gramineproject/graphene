#include "pal.h"
#include "pal_debug.h"

PAL_HANDLE wakeup;

int thread_func(void* args) {
    pal_printf("Enter thread\n");

    DkThreadDelayExecution(3000000);
    pal_printf("Thread sets event\n");

    char byte = 0;
    DkStreamWrite(wakeup, 0, 1, &byte, NULL);

    pal_printf("Leave thread\n");
    return 0;
}

int main(int argc, char** argv) {
    pal_printf("Enter main thread\n");

    PAL_HANDLE handles[3];
    handles[0] = DkStreamOpen("pipe:", PAL_ACCESS_RDWR, 0, 0, 0);
    handles[1] = DkStreamOpen("pipe:", PAL_ACCESS_RDWR, 0, 0, 0);
    handles[2] = DkStreamOpen("pipe:", PAL_ACCESS_RDWR, 0, 0, 0);
    wakeup     = handles[2];

    PAL_HANDLE thd = DkThreadCreate(&thread_func, NULL);
    if (!thd) {
        pal_printf("DkThreadCreate failed\n");
        return -1;
    }

    pal_printf("Waiting on event\n");

    PAL_FLG events[3]  = {PAL_WAIT_READ, PAL_WAIT_READ, PAL_WAIT_READ};
    PAL_FLG revents[3] = {0, 0, 0};

    PAL_BOL polled = DkStreamsWaitEvents(3, handles, events, revents, NO_TIMEOUT);
    if (!polled) {
        pal_printf("DkStreamsWaitEvents did not return any events\n");
        return -1;
    }

    if (revents[2])
        pal_printf("Event was called\n");

    pal_printf("Leave main thread\n");
    return 0;
}
