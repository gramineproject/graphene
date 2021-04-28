#include "pal.h"
#include "pal_regression.h"

/* prototype required due to -Wmissing-prototypes */
void preload_func2(void);

void preload_func2(void) {
    pal_printf("Preloaded Function 2 Called\n");
}

int main(int argc, char** argv, char** envp) {
    pal_printf("Binary 2 Preloaded\n");
    return 0;
}
