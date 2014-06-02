/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* This Hello World demostrate a simple multithread program */

#include "pal.h"
#include "pal_debug.h"

PAL_HANDLE event1, event2;

int thread_1 (void * args)
{
    pal_printf ("Enter Thread 1\n");

    DkThreadDelayExecution(3000);
    DkEventSet (event1);

    pal_printf ("Leave Thread 1\n");
    return 0;
}

int thread_2 (void * args)
{
    pal_printf ("Enter Thread 2\n");

    DkThreadDelayExecution(5000);
    DkEventSet (event2);

    pal_printf ("Leave Thread 2\n");
    return 0;
}

int main() {
    pal_printf ("Enter Main Thread\n");

    PAL_HANDLE thd1, thd2;

    event1 = DkNotificationEventCreate (0);
    event2 = DkNotificationEventCreate (0);

    thd1 = DkThreadCreate(&thread_1, 0, 0);

    if (thd1 == NULL) {
        pal_printf("DkThreadCreate failed\n");
        return -1;
    }

    thd2 = DkThreadCreate(&thread_2, 0, 0);

    if (thd2 == NULL) {
        pal_printf("DkThreadCreate failed\n");
        return -1;
    }

    PAL_HANDLE array[2];
    array[0] = event1;
    array[1] = event2;

    PAL_HANDLE hdl = DkObjectsWaitAny (2, array, NO_TIMEOUT);
    pal_printf("event%d is set\n", hdl == event1 ? 1 : 2);

    pal_printf("Leave Main Thread\n");
    return 0;
}

