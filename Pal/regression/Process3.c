#include "api.h"
#include "pal.h"
#include "pal_debug.h"

int main(int argc, char** argv, char** envp) {
    PAL_STR args[1] = {0};

    // Hack to differentiate parent from child
    if (argc == 1) {
        PAL_HANDLE child = DkProcessCreate(NULL, args);

        if (child)
            pal_printf("Create Process without Executable OK\n");
    }

    return 0;
}
