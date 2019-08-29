#include "pal.h"
#include "pal_debug.h"

void preload_func1(void) {
    pal_printf("Preloaded Function 1 Called\n");
}

int main(int argc, char** argv, char** envp) {
    pal_printf("Binary 1 Preloaded\n");
    return 0;
}
