#include "api.h"
#include "pal.h"
#include "pal_regression.h"

int main(int argc, char** argv) {
    int count = 0;

    pal_printf("In process: %s", argv[0]);
    for (int i = 1; i < argc; i++) {
        pal_printf(" %s", argv[i]);
    }
    pal_printf("\n");

    if (argc == 1) {
        uint64_t time = 0;
        if (DkSystemTimeQuery(&time) < 0) {
            pal_printf("DkSystemTimeQuery failed\n");
            return 1;
        }
        char time_arg[24];
        snprintf(time_arg, 24, "%ld", time);

        const char* newargs[4] = {"Process4", "0", time_arg, NULL};

        PAL_HANDLE proc = NULL;
        int ret = DkProcessCreate("file:Process4", newargs, &proc);

        if (ret < 0)
            pal_printf("Can't create process\n");

        DkObjectClose(proc);
        DkThreadDelayExecution(3000000);
    } else {
        count = atoi(argv[1]);

        if (count < 100) {
            count++;

            char count_arg[12];
            snprintf(count_arg, 12, "%d", count);
            const char* newargs[4] = {"Process4", count_arg, argv[2], NULL};

            PAL_HANDLE proc = NULL;
            int ret = DkProcessCreate("file:Process4", newargs, &proc);

            if (ret < 0)
                pal_printf("Can't create process\n");

            DkObjectClose(proc);
        } else {
            uint64_t end = 0;
            if (DkSystemTimeQuery(&end) < 0) {
                pal_printf("DkSystemTimeQuery failed\n");
                return 1;
            }
            uint64_t start = atol(argv[2]);
            pal_printf("wall time = %ld\n", end - start);
        }
    }

    DkProcessExit(0);
}
