/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal.h"
#include "pal_debug.h"

static int test_data = 0;
static int test_func (void) { return 0; }

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

    /* unique process ID */
    pal_printf("Process ID: %016x\n", pal_control.process_id);

    /* unique host ID */
    pal_printf("Host ID: %016x\n", pal_control.host_id);

    /* parent process */
    pal_printf("Parent Process: %016lx\n", pal_control.parent_process);

    /* test debug stream */
    char msg[] = "Written to Debug Stream\n";
    DkStreamWrite(pal_control.debug_stream, 0, sizeof(msg), msg, NULL);

    /* page size */
    pal_printf("Page Size: %d\n", pal_control.pagesize);
    /* Allocation Alignment */
    pal_printf("Allocation Alignment: %d\n", pal_control.alloc_align);

    /* user address range */
    pal_printf("User Address Range: %p - %p\n",
               pal_control.user_address.start,
               pal_control.user_address.end);

    if (pal_control.user_address.start &&
        pal_control.user_address.end &&
        pal_control.user_address.start < pal_control.user_address.end)
        pal_printf("User Address Range OK\n");

    /* executable address range */
    pal_printf("Executable Range: %p - %p\n",
               pal_control.executable_range.start,
               pal_control.executable_range.end);

    if (pal_control.executable_range.start &&
        pal_control.executable_range.end &&
        pal_control.executable_range.start < (void *) &test_data &&
        (void *) &test_data < pal_control.executable_range.end &&
        pal_control.executable_range.start < (void *) &test_func &&
        (void *) &test_func < pal_control.executable_range.end)
        pal_printf("Executable Range OK\n");

    pal_printf("CPU num: %d\n",      pal_control.cpu_info.cpu_num);
    pal_printf("CPU vendor: %s\n",   pal_control.cpu_info.cpu_vendor);
    pal_printf("CPU brand: %s\n",    pal_control.cpu_info.cpu_brand);
    pal_printf("CPU family: %d\n",   pal_control.cpu_info.cpu_family);
    pal_printf("CPU model: %d\n",    pal_control.cpu_info.cpu_model);
    pal_printf("CPU stepping: %d\n", pal_control.cpu_info.cpu_stepping);
    pal_printf("CPU flags: %s\n",    pal_control.cpu_info.cpu_flags);

    return 0;
}
