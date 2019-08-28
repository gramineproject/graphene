/* This Hello World demostrate a simple multithread program */

#define DO_BENCH 0

#include "api.h"
#include "pal.h"
#include "pal_debug.h"

int main(int argc, char** argv) {
    int count = 0;

#if DO_BENCH != 1
    pal_printf("In process: %s", argv[0]);
    for (int i = 1; i < argc; i++) {
        pal_printf(" %s", argv[i]);
    }
    pal_printf("\n");
#endif

    if (argc == 1) {
        unsigned long time = DkSystemTimeQuery();
        char time_arg[24];
        snprintf(time_arg, 24, "%ld", time);

        const char* newargs[4] = {"Process", "0", time_arg, NULL};

        PAL_HANDLE proc = DkProcessCreate("file:Process", newargs);

        if (!proc)
            pal_printf("Can't create process\n");

        DkObjectClose(proc);
        DkThreadDelayExecution(30000000);
    } else {
        count = atoi(argv[1]);

        if (count < 100) {
            count++;

            char count_arg[8];
            snprintf(count_arg, 8, "%d", count);
            const char* newargs[4] = {"Process", count_arg, argv[2], NULL};

            PAL_HANDLE proc = DkProcessCreate("file:Process", newargs);

            if (!proc)
                pal_printf("Can't creste process\n");

            DkObjectClose(proc);
        } else {
            unsigned long end   = DkSystemTimeQuery();
            unsigned long start = atol(argv[2]);
            pal_printf("wall time = %ld\n", end - start);
        }
    }

    DkProcessExit(0);
    return 0;
}
