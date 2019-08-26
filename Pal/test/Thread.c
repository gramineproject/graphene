/* This Hello World demostrate a simple multithread program */
#include "pal.h"
#include "pal_debug.h"

int thread_1(void* args) {
    pal_printf("Enter Thread 1\n");

    DkThreadDelayExecution(3000);

    pal_printf("Leave Thread 1\n");
    return 0;
}

int thread_2(void* args) {
    pal_printf("Enter Thread 2\n");
    pal_printf("Parent do suspension\n");

    DkThreadDelayExecution(3000);

    pal_printf("Parent do reload\n");
    pal_printf("Leave Thread 2\n");
    return 0;
}

int main() {
    pal_printf("Enter Main Thread\n");

    PAL_HANDLE thd1, thd2;

    thd1 = DkThreadCreate(&thread_1, NULL);

    if (thd1 == NULL) {
        pal_printf("DkThreadCreate failed\n");
        return -1;
    }

    thd2 = DkThreadCreate(&thread_2, NULL);

    if (thd2 == NULL) {
        pal_printf("DkThreadCreate failed\n");
        return -1;
    }

    pal_printf("Leave Main Thread\n");
    return 0;
}
