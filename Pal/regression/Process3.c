#include "api.h"
#include "pal.h"
#include "pal_regression.h"

int main(int argc, char** argv, char** envp) {
    PAL_STR args[1] = {0};

    // Hack to differentiate parent from child
    if (argc == 1) {
        PAL_HANDLE child = NULL;
        int ret = DkProcessCreate(args, &child);

        if (ret == 0 && child)
            pal_printf("Creating child OK\n");
    }

    return 0;
}
