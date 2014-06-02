/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal.h"
#include "pal_debug.h"

int main(int argc, char ** argv)
{
    char * name = "parent";

    if (argc == 1) {
        const char * args[3];
        char uri[20], uri2[20];

        pal_snprintf(uri2, 20, "file:%s", argv[0]);

        args[0] = "Ipc";
        args[1] = uri;
        args[2] = NULL;

        void * mem = DkVirtualMemoryAlloc
                        (NULL, 4096, 0, PAL_PROT_READ|PAL_PROT_WRITE);

        pal_printf("mem = %p\n", mem);
        pal_snprintf((char *) mem, 4096, "Hello World");

        uint64_t key = 0;

        PAL_HANDLE chdl = DkCreatePhysicalMemoryChannel(&key);

        if (chdl == NULL) {
            pal_printf ("(parent) StreamOpen Failed ---"
                         " Make sure gipc module is loaded\n");
            return 0;
        }

        pal_snprintf(uri, 20, "gipc:%lld", key);

        PAL_HANDLE phdl = DkProcessCreate (uri2, 0, args);

        if (phdl == NULL)
            pal_printf ("ProcessCreate Failed\n");

        unsigned long size = 4096;
        DkPhysicalMemoryCommit (chdl, 1, &mem, &size, 0);
        DkObjectClose(chdl);

        char x;
        int rv = DkStreamRead(phdl, 0, 1, &x, NULL, 0);
        if (rv != 1) {
            pal_printf("Failed to get exit signal from child, %d\n", rv);
            return -1;
        }
    }
    else {
        name = argv[1];

        PAL_HANDLE chdl = DkStreamOpen (name, 0, 0, 0, 0);

        if (chdl == NULL) {
            pal_printf("(child) StreamOpen Failed\n");
            return 0;
        }

        PAL_BUF addr = NULL;
        PAL_NUM size = 4096;
        PAL_FLG prot = PAL_PROT_READ|PAL_PROT_WRITE;

        int len = DkPhysicalMemoryMap (chdl, 1, &addr, &size, &prot);

        if (!len) {
            pal_printf("PhysicalMemoryMap Failed\n");
            return 0;
        }

        pal_printf("(child) mem = %p\n", addr);
        pal_printf("(child) receive string: %s\n", (char *) addr);

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

