/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* This Hello World demostrate a simple multithread program */

#include "pal.h"
#include "pal_debug.h"

static PAL_HANDLE event1;

int count = 0;

int thread_1(void* args)
{
    DkThreadDelayExecution(1000);

    pal_printf("In Thread 1\n");

    while (count < 100)
        count++;

    DkEventSet(event1);
    DkThreadExit();

    return 0;
}

int main (int argc, char ** argv)
{
    pal_printf ("Enter Main Thread\n");

    PAL_HANDLE thd1;

    event1 = DkNotificationEventCreate(0);
    if (event1 == NULL) {
        pal_printf("DkNotificationEventCreate failed\n");
        return -1;
    }

    thd1 = DkThreadCreate(&thread_1, 0, 0);

    if (thd1 == NULL) {
        pal_printf("DkThreadCreate failed\n");
        return -1;
    }

    DkObjectsWaitAny(1, &event1, NO_TIMEOUT);

    if (count < 100)
        return -1;

    DkObjectsWaitAny(1, &event1, NO_TIMEOUT);

    pal_printf("Leave Main Thread\n");
    return 0;
}

