/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* This Hello World demostrate a simple multithread program */
#include "pal.h"
#include "pal_debug.h"

PAL_HANDLE wakeup;

int thread (void * args)
{
    pal_printf("Enter Thread\n");

    DkThreadDelayExecution(3000000);
    pal_printf("set event\n");

    char byte = 0;
    DkStreamWrite(wakeup, 0, 1, &byte, NULL);

    pal_printf("Leave Thread\n");
    return 0;
}

int main() {
    pal_printf("Enter Main Thread\n");

    PAL_HANDLE handles[3];
    handles[0] = DkStreamOpen("pipe:", PAL_ACCESS_RDWR, 0, 0, 0);
    handles[1] = DkStreamOpen("pipe:", PAL_ACCESS_RDWR, 0, 0, 0);
    handles[2] = DkStreamOpen("pipe:", PAL_ACCESS_RDWR, 0, 0, 0);
    wakeup = handles[2];

    PAL_HANDLE thd = DkThreadCreate(&thread, NULL, 0);

    if (thd == NULL) {
        pal_printf("DkThreadCreate failed\n");
        return -1;
    }

    pal_printf("wait on event\n");

    PAL_HANDLE hdl = DkObjectsWaitAny(3, handles, NO_TIMEOUT);

    if (hdl == wakeup)
        pal_printf("events is called\n");

    pal_printf("Leave Main Thread\n");
    return 0;
}

