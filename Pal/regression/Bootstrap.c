#include <string.h>

#include "pal.h"
#include "pal_debug.h"

int main(int argc, char** argv, char** envp) {
    /* check if the program is loaded */
    pal_printf("User Program Started\n");

    /* check control block */
    /* check executable name */
    pal_printf("Loaded Executable: %s\n", pal_control.executable);

    /* check arguments */
    pal_printf("# of Arguments: %d\n", argc);
    for (int i = 0; i < argc; i++) {
        pal_printf("argv[%d] = %s\n", i, argv[i]);
    }

    /* unique process ID */
    pal_printf("Process ID: %016lx\n", pal_control.process_id);

    /* parent process */
    pal_printf("Parent Process: %p\n", pal_control.parent_process);

    /* test debug stream */
    char* msg = "Written to Debug Stream\n";
    DkDebugLog(msg, strlen(msg));

    /* Allocation Alignment */
    pal_printf("Allocation Alignment: %ld\n", pal_control.alloc_align);

    /* user address range */
    pal_printf("User Address Range: %p - %p\n", pal_control.user_address.start,
               pal_control.user_address.end);

    if (pal_control.user_address.start && pal_control.user_address.end &&
        pal_control.user_address.start < pal_control.user_address.end)
        pal_printf("User Address Range OK\n");

    pal_printf("CPU num: %ld\n", pal_control.cpu_info.online_logical_cores);
    pal_printf("CPU vendor: %s\n", pal_control.cpu_info.cpu_vendor);
    pal_printf("CPU brand: %s\n", pal_control.cpu_info.cpu_brand);
    pal_printf("CPU family: %ld\n", pal_control.cpu_info.cpu_family);
    pal_printf("CPU model: %ld\n", pal_control.cpu_info.cpu_model);
    pal_printf("CPU stepping: %ld\n", pal_control.cpu_info.cpu_stepping);
    pal_printf("CPU flags: %s\n", pal_control.cpu_info.cpu_flags);

    return 0;
}
