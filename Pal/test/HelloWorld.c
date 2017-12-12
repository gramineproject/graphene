/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* This Hello World simply print out "Hello World" */

#include "pal.h"
#include "pal_debug.h"

char str[] = "Hello World\n";

int main (int argc, char ** argv, char ** envp)
{
    pal_printf("start program: %s\n", pal_control.executable);

    PAL_HANDLE out = DkStreamOpen("dev:tty", PAL_ACCESS_WRONLY, 0, 0, 0);

    if (out == NULL) {
        pal_printf("DkStreamOpen failed\n");
        return -1;
    }

    int bytes = DkStreamWrite(out, 0, sizeof(str) - 1, str, NULL);

    if (bytes < 0) {
        pal_printf("DkStreamWrite failed\n");
        return -1;
    }

    DkObjectClose(out);
    return 0;
}
