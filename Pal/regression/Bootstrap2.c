#include "pal.h"
#include "pal_debug.h"

int main(int argc, char** argv, char** envp) {
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
    for (int i = 0; i < argc; i++) {
        pal_printf("argv[%d] = %s\n", i, argv[i]);
    }

    return 0;
}
