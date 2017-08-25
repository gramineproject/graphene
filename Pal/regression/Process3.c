/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal.h"
#include "pal_debug.h"
#include "api.h"

int main (int argc, char ** argv, char ** envp)
{
    PAL_STR args[1] = { 0 };

    // Hack to differentiate parent from child
    if (argc == 1) {
        PAL_HANDLE child = DkProcessCreate(NULL, 0, args);

        if (child)
            pal_printf("Create Process without Executable OK\n");
    }

    return 0;
}
