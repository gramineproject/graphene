#include "pal.h"
#include "pal_debug.h"

int main(int argc, char** argv, char** envp) {
    long sleeping = 3000000;

    pal_printf("Enter Main Thread\n");
    pal_printf("Sleeping %ld microsecond...\n", sleeping);
    DkThreadDelayExecution(sleeping);
    pal_printf("Leave Main Thread\n");

    return 0;
}
