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
