#include <includes.h>

#define PRINT_STR pal_printf("%s invoked\n", __func__)

/* (a) Specify a single init routine via Makefile.
 * Populates DT_INIT */

void __dt_init(void) {
    PRINT_STR;
}

/* (b) Specify multiple independent init routines via attributes.
 * Populates DT_INIT_ARRAY */

__attribute__((constructor)) void __dt_init_array1(void) {
    PRINT_STR;
}

__attribute__((constructor)) void __dt_init_array2(void) {
    PRINT_STR;
}
