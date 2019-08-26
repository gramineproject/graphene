#include "pal.h"
#include "pal_debug.h"

void preload_func1(void);
void preload_func2(void);

int main(int argc, char** argv, char** envp) {
    /* check if the program is loaded */
    pal_printf("User Program Started\n");

    /* check control block */
    /* check executable name */
    pal_printf("Loaded Executable: %s\n", pal_control.executable);

    preload_func1();
    preload_func2();

    return 0;
}
