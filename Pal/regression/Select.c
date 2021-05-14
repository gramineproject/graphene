#include "pal.h"
#include "pal_error.h"
#include "pal_regression.h"

PAL_HANDLE wakeup;

static int thread_func(void* args) {
    pal_printf("Enter thread\n");

    PAL_HANDLE sleep_handle = NULL;
    if (DkEventCreate(&sleep_handle, /*init_signaled=*/false, /*auto_clear=*/false) < 0) {
        pal_printf("DkEventCreate failed\n");
        DkProcessExit(1);
    }

    uint64_t timeout = 3000000;
    int ret = DkEventWait(sleep_handle, &timeout);
    if (ret != -PAL_ERROR_TRYAGAIN) {
        pal_printf("DkEventWait failed\n");
        DkProcessExit(1);
    }

    pal_printf("Thread sets event\n");

    char byte = 0;
    size_t size = 1;
    DkStreamWrite(wakeup, 0, &size, &byte, NULL);

    pal_printf("Leave thread\n");
    return 0;
}

int main(int argc, char** argv) {
    pal_printf("Enter main thread\n");

    PAL_HANDLE handles[3];
    int ret = DkStreamOpen("pipe:", PAL_ACCESS_RDWR, 0, 0, 0, &handles[0]);
    if (ret < 0) {
        pal_printf("DkStreamOpen failed\n");
        return 1;
    }
    ret = DkStreamOpen("pipe:", PAL_ACCESS_RDWR, 0, 0, 0, &handles[1]);
    if (ret < 0) {
        pal_printf("DkStreamOpen failed\n");
        return 1;
    }
    ret = DkStreamOpen("pipe:", PAL_ACCESS_RDWR, 0, 0, 0, &handles[2]);
    if (ret < 0) {
        pal_printf("DkStreamOpen failed\n");
        return 1;
    }
    wakeup = handles[2];

    PAL_HANDLE thd = NULL;
    ret = DkThreadCreate(&thread_func, NULL, &thd);
    if (ret < 0) {
        pal_printf("DkThreadCreate failed\n");
        return 1;
    }

    pal_printf("Waiting on event\n");

    PAL_FLG events[3]  = {PAL_WAIT_READ, PAL_WAIT_READ, PAL_WAIT_READ};
    PAL_FLG revents[3] = {0, 0, 0};

    ret = DkStreamsWaitEvents(3, handles, events, revents, NO_TIMEOUT);
    if (ret < 0) {
        pal_printf("DkStreamsWaitEvents did not return any events\n");
        return 1;
    }

    if (revents[2])
        pal_printf("Event was called\n");

    pal_printf("Leave main thread\n");
    return 0;
}
