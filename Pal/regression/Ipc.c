/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal.h"
#include "pal_debug.h"
#include "api.h"

#define UNIT pal_control.alloc_align

static const char * volatile message = NULL;

void handler (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    if (message)
        pal_printf(message);

    while (*(unsigned char *) context->rip != 0x90)
        context->rip++;

    DkExceptionReturn(event);

}

int main (int argc, char ** argv, char ** envp)
{
    char gipc_uri[20];
    int ret;

    DkSetExceptionHandler(handler, PAL_EVENT_MEMFAULT, 0);

    if (argc > 1 && !memcmp(argv[1], "Child", 6)) {
        /* private memory */

        ret = DkStreamRead(pal_control.parent_process, 0, 20, gipc_uri,
                           NULL, 0);

        if (ret > 0) {
            PAL_HANDLE ipc1 = DkStreamOpen(gipc_uri, 0, 0, 0, 0);

            if (ipc1) {
                pal_printf("Join Physical Memory Store OK\n");

                PAL_PTR mem_addr = 0;
                PAL_NUM mem_size = UNIT;
                PAL_FLG mem_prot = PAL_PROT_READ|PAL_PROT_WRITE;

                ret = DkPhysicalMemoryMap(ipc1, 1, &mem_addr, &mem_size,
                                          &mem_prot);

                if (ret > 0) {
                    pal_printf("[Test 1] Physical Memory Map   : %s\n",
                               (char *) mem_addr);
                    memcpy((void *) mem_addr, "Hello World, Bob", 20);
                    pal_printf("[Test 1] Receiver After  Map   : %s\n",
                               (char *) mem_addr);
                }

                ret = 0;
                DkStreamWrite(pal_control.parent_process, 0, sizeof(int),
                              &ret, NULL);
                DkObjectClose(ipc1);
            }
        }

        /* private untouched memory */

        ret = DkStreamRead(pal_control.parent_process, 0, 20, gipc_uri,
                           NULL, 0);

        if (ret > 0) {
            PAL_HANDLE ipc2 = DkStreamOpen(gipc_uri, 0, 0, 0, 0);

            if (ipc2) {
                pal_printf("Join Physical Memory Store OK\n");

                PAL_PTR mem_addr = 0;
                PAL_NUM mem_size = UNIT;
                PAL_FLG mem_prot = PAL_PROT_READ|PAL_PROT_WRITE;

                ret = DkPhysicalMemoryMap(ipc2, 1, &mem_addr, &mem_size,
                                          &mem_prot);

                if (ret > 0) {
                    pal_printf("[Test 2] Physical Memory Map   : %s\n",
                               (char *) mem_addr);
                    memcpy((void *) mem_addr, "Hello World, Bob", 20);
                    pal_printf("[Test 2] Receiver After  Map   : %s\n",
                               (char *) mem_addr);
                }

                ret = 0;
                DkStreamWrite(pal_control.parent_process, 0, sizeof(int),
                              &ret, NULL);
                DkStreamDelete(ipc2, 0);
                DkObjectClose(ipc2);
            }
        }

        /* file-backed memory */

        ret = DkStreamRead(pal_control.parent_process, 0, 20, gipc_uri,
                           NULL, 0);

        if (ret > 0) {
            PAL_HANDLE ipc3 = DkStreamOpen(gipc_uri, 0, 0, 0, 0);

            if (ipc3) {
                pal_printf("Join Physical Memory Store OK\n");

                PAL_PTR mem_addr = 0;
                PAL_NUM mem_size = UNIT;
                PAL_FLG mem_prot = PAL_PROT_READ|PAL_PROT_WRITE;

                ret = DkPhysicalMemoryMap(ipc3, 1, &mem_addr, &mem_size,
                                          &mem_prot);

                if (ret > 0) {
                    pal_printf("[Test 3] Physical Memory Map   : %s\n",
                               (char *) mem_addr);
                    memcpy((void *) mem_addr, "Hello World, Bob", 20);
                    pal_printf("[Test 3] Receiver After  Map   : %s\n",
                               (char *) mem_addr);
                }

                ret = 0;
                DkStreamWrite(pal_control.parent_process, 0, sizeof(int),
                              &ret, NULL);
                DkObjectClose(ipc3);
            }
        }

        /* file-backed memory beyond file size */

        ret = DkStreamRead(pal_control.parent_process, 0, 20, gipc_uri,
                           NULL, 0);

        if (ret > 0) {
            PAL_HANDLE ipc4 = DkStreamOpen(gipc_uri, 0, 0, 0, 0);

            if (ipc4) {
                pal_printf("Join Physical Memory Store OK\n");

                PAL_PTR mem_addr = 0;
                PAL_NUM mem_size = UNIT;
                PAL_FLG mem_prot = PAL_PROT_READ|PAL_PROT_WRITE;

                ret = DkPhysicalMemoryMap(ipc4, 1, &mem_addr, &mem_size,
                                          &mem_prot);

                if (ret > 0) {
                    message = "[Test 4] Physical Memory Map   : Memory Fault\n";
                    *(volatile int *) mem_addr;
                    asm volatile("nop");
                    message = NULL;
                }

                ret = 0;
                DkStreamWrite(pal_control.parent_process, 0, sizeof(int),
                              &ret, NULL);
                DkObjectClose(ipc4);
            }
        }

        /* large memory */

        ret = DkStreamRead(pal_control.parent_process, 0, 20, gipc_uri,
                           NULL, 0);

        if (ret > 0) {
            PAL_HANDLE ipc5 = DkStreamOpen(gipc_uri, 0, 0, 0, 0);

            if (ipc5) {
                pal_printf("Join Physical Memory Store OK\n");

                PAL_PTR mem_addr = 0;
                PAL_NUM mem_size = UNIT * 1024 * 64;
                PAL_FLG mem_prot = PAL_PROT_READ|PAL_PROT_WRITE;

                ret = DkPhysicalMemoryMap(ipc5, 1, &mem_addr, &mem_size,
                                          &mem_prot);

                if (ret > 0) {
                    pal_printf("[Test 5] Physical Memory Map   : %s\n",
                               (char *) mem_addr + UNIT * 1024);
                }

                ret = 0;
                DkStreamWrite(pal_control.parent_process, 0, sizeof(int),
                              &ret, NULL);
                DkObjectClose(ipc5);
            }
        }
    } else {
        PAL_STR args[3] = { "Ipc", "Child", 0 };
        PAL_HANDLE proc = DkProcessCreate("file:Ipc", 0, args);

        if (!proc)
            return 0;

        /* private memory */

        PAL_NUM key1;
        PAL_HANDLE ipc1 = DkCreatePhysicalMemoryChannel(&key1);

        if (ipc1) {
            snprintf(gipc_uri, 20, "gipc:%lld", key1);
            pal_printf("Create Physical Memory Store OK\n");

            void * mem1 =
                (void *) DkVirtualMemoryAlloc(NULL, UNIT, 0,
                                              PAL_PROT_READ|PAL_PROT_WRITE);

            if (mem1) {
                memcpy(mem1, "Hello World", 20);

                PAL_PTR mem_addr = mem1;
                PAL_NUM mem_size = UNIT;

                if (DkPhysicalMemoryCommit(ipc1, 1, &mem_addr, &mem_size, 0)) {
                    pal_printf("[Test 1] Physical Memory Commit OK\n");
                    memcpy(mem1, "Hello World, Alice", 20);
                    pal_printf("[Test 1] Sender   After  Commit: %s\n",
                               (char *) mem1);
                    DkStreamWrite(proc, 0, 20, gipc_uri, NULL);
                    memcpy(mem1, "Alice, Hello World", 20);
                    pal_printf("[Test 1] Sender   Before Map   : %s\n",
                               (char *) mem1);
                    DkStreamRead(proc, 0, sizeof(int), &ret, NULL, 0);
                    pal_printf("[Test 1] Sender   After  Map   : %s\n",
                               (char *) mem1);
                }
            }

            DkObjectClose(ipc1);
        }

        /* private untouched memory */

        PAL_NUM key2;
        PAL_HANDLE ipc2 = DkCreatePhysicalMemoryChannel(&key2);

        if (ipc2) {
            snprintf(gipc_uri, 20, "gipc:%lld", key2);
            pal_printf("Create Physical Memory Store OK\n");

            void * mem2 =
                (void *) DkVirtualMemoryAlloc(NULL, UNIT, 0,
                                              PAL_PROT_READ|PAL_PROT_WRITE);

            if (mem2) {
                PAL_PTR mem_addr = mem2;
                PAL_NUM mem_size = UNIT;

                if (DkPhysicalMemoryCommit(ipc2, 1, &mem_addr, &mem_size, 0)) {
                    pal_printf("[Test 2] Physical Memory Commit OK\n");
                    memcpy(mem2, "Hello World, Alice", 20);
                    pal_printf("[Test 2] Sender   After  Commit: %s\n",
                               (char *) mem2);
                    DkStreamWrite(proc, 0, 20, gipc_uri, NULL);
                    memcpy(mem2, "Alice, Hello World", 20);
                    pal_printf("[Test 2] Sender   Before Map   : %s\n",
                               (char *) mem2);
                    DkStreamRead(proc, 0, sizeof(int), &ret, NULL, 0);
                    pal_printf("[Test 2] Sender   After  Map   : %s\n",
                               (char *) mem2);
                }
            }

            DkObjectClose(ipc2);
        }

        /* file-backed memory */

        PAL_NUM key3;
        PAL_HANDLE ipc3 = DkCreatePhysicalMemoryChannel(&key3);

        if (ipc3) {
            snprintf(gipc_uri, 20, "gipc:%lld", key3);
            pal_printf("Create Physical Memory Store OK\n");

            void * mem3 = NULL;
            PAL_HANDLE file1 = DkStreamOpen("file:ipc_mapping.tmp",
                                            PAL_ACCESS_RDWR, 0, 0, 0);

            if (file1) {
                mem3 = (void *) DkStreamMap(file1, NULL,
                                            PAL_PROT_READ|PAL_PROT_WRITE,
                                            0, UNIT);
                DkObjectClose(file1);
            }

            if (mem3) {
                PAL_PTR mem_addr = mem3;
                PAL_NUM mem_size = UNIT;

                if (DkPhysicalMemoryCommit(ipc3, 1, &mem_addr, &mem_size, 0)) {
                    pal_printf("[Test 3] Physical Memory Commit OK\n");
                    DkStreamWrite(proc, 0, 20, gipc_uri, NULL);
                    pal_printf("[Test 3] Sender   After  Commit: %s\n",
                               (char *) mem3);
                    DkStreamRead(proc, 0, sizeof(int), &ret, NULL, 0);
                    pal_printf("[Test 3] Sender   After  Map   : %s\n",
                               (char *) mem3);
                }
            }

            DkObjectClose(ipc3);
        }

        /* file-backed memory beyond file size */

        PAL_NUM key4;
        PAL_HANDLE ipc4 = DkCreatePhysicalMemoryChannel(&key4);

        if (ipc4) {
            snprintf(gipc_uri, 20, "gipc:%lld", key4);
            pal_printf("Create Physical Memory Store OK\n");

            void * mem4 = NULL;
            PAL_HANDLE file2 = DkStreamOpen("file:ipc_mapping.tmp",
                                            PAL_ACCESS_RDWR, 0, 0, 0);

            if (file2) {
                mem4 = (void *) DkStreamMap(file2, NULL,
                                            PAL_PROT_READ|PAL_PROT_WRITE,
                                            UNIT, UNIT);
                DkObjectClose(file2);
            }

            if (mem4) {
                PAL_PTR mem_addr = mem4;
                PAL_NUM mem_size = UNIT;

                if (DkPhysicalMemoryCommit(ipc4, 1, &mem_addr, &mem_size, 0)) {
                    pal_printf("[Test 4] Physical Memory Commit OK\n");
                    DkStreamWrite(proc, 0, 20, gipc_uri, NULL);
                    DkStreamRead(proc, 0, sizeof(int), &ret, NULL, 0);
                }
            }

            DkObjectClose(ipc4);
        }

        /* large memory */

        PAL_NUM key5;
        PAL_HANDLE ipc5 = DkCreatePhysicalMemoryChannel(&key5);

        if (ipc5) {
            snprintf(gipc_uri, 20, "gipc:%lld", key5);
            pal_printf("Create Physical Memory Store OK\n");

            void * mem5 =
                (void *) DkVirtualMemoryAlloc(NULL, UNIT * 1024 * 64, 0,
                                              PAL_PROT_READ|PAL_PROT_WRITE);

            if (mem5) {
                pal_printf("Touch Memory at %p\n", mem5 + UNIT * 1024);

                memcpy(mem5 + UNIT * 1024, "Hello World", 20);

                PAL_PTR mem_addr = mem5;
                PAL_NUM mem_size = UNIT * 1024 * 64;

                DkStreamWrite(proc, 0, 20, gipc_uri, NULL);

                if (DkPhysicalMemoryCommit(ipc5, 1, &mem_addr, &mem_size, 0)) {
                    pal_printf("[Test 5] Physical Memory Commit OK\n");
                    DkStreamRead(proc, 0, sizeof(int), &ret, NULL, 0);
                }
            }

            DkObjectClose(ipc1);
        }
    }

    return 0;
}
