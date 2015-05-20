/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal.h"
#include "pal_debug.h"

int main (int argc, char ** argv, char ** envp)
{
    /* check if the program is loaded */
    pal_printf("User Program Started\n");

    /* check control block */
    /* check executable name */
    pal_printf("Loaded Executable: %s\n", pal_control.executable);

    /* check manifest name */
    char manifest[30] = "";
    DkStreamGetName(pal_control.manifest_handle, manifest, 30);
    pal_printf("Loaded Manifest: %s\n", manifest);

    /* check arguments */
    pal_printf("# of Arguments: %d\n", argc);
    for (int i = 0 ; i < argc ; i++)
        pal_printf("argv[%d] = %s\n", i, argv[i]);

    return 0;
}
