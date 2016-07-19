/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal.h"
#include "pal_debug.h"
#include "api.h"

int main (int argc, char ** argv, char ** envp)
{
    char buffer1[20] = "Hello World 1", buffer2[20] = "Hello World 2";
    char buffer3[20], buffer4[20], buffer5[20];
    int ret;

    if (argc > 1 && !memcmp(argv[1], "Child", 6)) {
        pal_printf("Child Process Created\n");

        /* check manifest name */
        char manifest[30] = "";
        DkStreamGetName(pal_control.manifest_handle, manifest, 30);
        pal_printf("Loaded Manifest: %s\n", manifest);

        /* check arguments */
        pal_printf("# of Arguments: %d\n", argc);
        for (int i = 0 ; i < argc ; i++)
            pal_printf("argv[%d] = %s\n", i, argv[i]);

        DkStreamWrite(pal_control.parent_process, 0, 20, buffer1, NULL);

        ret = DkStreamRead(pal_control.broadcast_stream, 0, 20, buffer5, NULL, 0);
        if (ret > 0)
            pal_printf("Broadcast Read: %s\n", buffer5);

        ret = DkStreamWrite(pal_control.parent_process, 0, 20, buffer1, NULL);
        if (ret > 0)
            pal_printf("Process Write 1 OK\n");

        ret = DkStreamRead(pal_control.parent_process, 0, 20, buffer4, NULL, 0);
        if (ret > 0)
            pal_printf("Process Read 2: %s\n", buffer4);

    } else {
        PAL_STR args[3] = { "Process", "Child", 0 };
        PAL_HANDLE children[3];

        for (int i = 0 ; i < 3 ; i++) {
            pal_printf("Creating process\n");

            children[i] = DkProcessCreate("file:Process", 0, args);

            if (children[i]) {
                pal_printf("Process created %d\n", i + 1);
                DkStreamRead(children[i], 0, 20, buffer4, NULL, 0);
            }
        }

        pal_printf("Broadcasting message\n");

        ret = DkStreamWrite(pal_control.broadcast_stream, 0, 20, buffer1, NULL);
        if (ret > 0)
            pal_printf("Broadcast Write OK\n");

        for (int i = 0 ; i < 3 ; i++)
            if (children[i]) {
                ret = DkStreamRead(children[i], 0, 20, buffer3, NULL, 0);
                if (ret > 0)
                    pal_printf("Process Read 1: %s\n", buffer3);

                ret = DkStreamWrite(children[i], 0, 20, buffer2, NULL);
                if (ret > 0)
                    pal_printf("Process Write 2 OK\n");
            }
    }

    return 0;
}
