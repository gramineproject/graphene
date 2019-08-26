/* This Hello World simply print out "Hello World" */

#include "pal.h"
#include "pal_debug.h"

int count = 0;
int i     = 0;

void handler(PAL_PTR event, PAL_NUM arg, PAL_CONTEXT* context) {
    pal_printf("failure in the handler: 0x%08lx\n", arg);
    count++;

    if (count == 30)
        DkProcessExit(0);

    DkExceptionReturn(event);
}

int main(void) {
    pal_printf("Enter Main Thread\n");

    DkSetExceptionHandler(handler, PAL_EVENT_ARITHMETIC_ERROR);

    i = 1 / i;

    pal_printf("Leave Main Thread\n");
    return 0;
}
