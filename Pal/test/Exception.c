/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* This Hello World simply print out "Hello World" */

#include "pal.h"
#include "pal_debug.h"

int count = 0;
int i = 0;

void handler (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    pal_printf("failure in the handler: %p\n", arg);
    count++;

    if (count == 30)
        DkProcessExit(0);

    DkExceptionReturn(event);
}

int main (void)
{
    pal_printf("Enter Main Thread\n");

    DkSetExceptionHandler(handler, PAL_EVENT_DIVZERO, 0);

    i =  1 / i;

    pal_printf("Leave Main Thread\n");
    return 0;
}
