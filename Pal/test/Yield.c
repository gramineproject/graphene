#include "pal.h"
#include "pal_debug.h"

PAL_HANDLE parent_thread, child_thread;

int child(void* args) {
    int i;
    pal_printf("Enter Child Thread\n");

    for (i = 0; i < 100; i++) {
        DkThreadDelayExecution(3000);
        DkThreadResume(parent_thread);
        pal_printf("parent yielded\n");
    }

    pal_printf("Leave Child Thread\n");
    return 0;
}

int main(void) {
    int i;
    pal_printf("Enter Parent Thread\n");

    parent_thread = pal_control.first_thread;
    child_thread  = DkThreadCreate(&child, NULL);

    if (child_thread == NULL) {
        pal_printf("DkThreadCreate failed\n");
        return -1;
    }

    for (i = 0; i < 100; i++) {
        DkThreadDelayExecution(3000);
        DkThreadResume(child_thread);
        pal_printf("child yielded\n");
    }

    pal_printf("Leave Parent Thread\n");
    return 0;
}
