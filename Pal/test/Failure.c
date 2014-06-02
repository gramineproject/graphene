/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* This Hello World simply print out "Hello World" */

#include "pal.h"
#include "pal_error.h"
#include "pal_debug.h"

int handled = 0;

void FailureHandler (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    pal_printf("Failure notified: %s\n",
               pal_errstring[(unsigned long) arg]);

    handled = 1;
    DkExceptionReturn(event);
}

int main (int argc, char ** argv, char ** envp)
{
    pal_printf("Enter Main Thread\n");

    DkSetExceptionHandler(FailureHandler, PAL_EVENT_FAILURE, 0);

    PAL_HANDLE out = DkStreamOpen("foo:unknown", PAL_ACCESS_WRONLY, 0, 0, 0);

    if (!out && !handled) {
        pal_printf("DkStreamOpen failed\n");
        return -1;
    }

    pal_printf("Leave Main Thread\n");
    return 0;
}
