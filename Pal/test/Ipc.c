/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal.h"
#include "pal_debug.h"
#include "api.h"

int main(int argc, char ** argv)
{
    char * name = "parent";

    if (argc == 1) {
        const char * args[3];
        char uri[20];

        args[0] = "Ipc";
        args[1] = uri;
        args[2] = NULL;

        void * mem = (void *) DkVirtualMemoryAlloc(NULL,
                                                   pal_control.alloc_align, 0,
                                                   PAL_PROT_READ|PAL_PROT_WRITE);

        pal_printf("mem = %p\n", mem);
        snprintf((char *) mem, 4096, "Hello World");

        PAL_NUM key = 0;
        PAL_HANDLE chdl = DkCreatePhysicalMemoryChannel(&key);

        if (chdl == NULL) {
            pal_printf ("(parent) DkCreatePhysicalMemoryChannel Failed,"
                         " Make sure gipc module is loaded\n");
            return 0;
        }

        snprintf(uri, 20, "gipc:%lld", key);

        PAL_HANDLE phdl = DkProcessCreate("file:Ipc", 0, args);

        if (phdl == NULL)
            pal_printf ("ProcessCreate Failed\n");

        PAL_PTR addr = (PAL_PTR) mem;
        PAL_NUM size = pal_control.alloc_align;
        DkPhysicalMemoryCommit(chdl, 1, &addr, &size, 0);
        DkObjectClose(chdl);

        char x;
        int rv = DkStreamRead(phdl, 0, 1, &x, NULL, 0);
        if (rv != 1) {
            pal_printf("Failed to get exit signal from child, %d\n", rv);
            return -1;
        }
    } else {
        name = argv[1];

        PAL_HANDLE chdl = DkStreamOpen(name, 0, 0, 0, 0);

        if (chdl == NULL) {
            pal_printf("(child) StreamOpen Failed\n");
            return 0;
        }

        PAL_PTR addr = NULL;
        PAL_NUM size = pal_control.alloc_align;
        PAL_FLG prot = PAL_PROT_READ|PAL_PROT_WRITE;

        int len = DkPhysicalMemoryMap (chdl, 1, &addr, &size, &prot);

        if (!len) {
            pal_printf("PhysicalMemoryMap Failed\n");
            return 0;
        }

        pal_printf("(child) mem = %p\n", addr);
        pal_printf("(child) receive string: %s\n", (char *) addr);

        DkStreamDelete(chdl, 0);
        DkObjectClose(chdl);

        // Write a byte to the parent
        int rv = DkStreamWrite(pal_control.parent_process, 0, 1, "z", NULL);
        if (rv < 0) {
            pal_printf("Failed to write an exit byte\n");
            return -1;
        }
    }

    pal_printf("Enter Main Thread (%s)\n", name);

    DkThreadDelayExecution (3000);

    pal_printf("Leave Main Thread\n");
    return 0;
}

