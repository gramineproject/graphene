#include "pal.h"
#include "pal_debug.h"
#include "pal_error.h"

int handled = 0;

static void FailureHandler(PAL_NUM arg, PAL_CONTEXT* context) {
    pal_printf("Failure notified: %s\n", pal_strerror((unsigned long)arg));

    handled = 1;
}

int main(int argc, char** argv, char** envp) {
    pal_printf("Enter Main Thread\n");

    DkSetExceptionHandler(FailureHandler, PAL_EVENT_FAILURE);

    PAL_HANDLE out = DkStreamOpen("foo:unknown", PAL_ACCESS_WRONLY, 0, 0, 0);

    if (!out && !handled) {
        pal_printf("DkStreamOpen failed\n");
        return -1;
    }

    pal_printf("Leave Main Thread\n");
    return 0;
}
