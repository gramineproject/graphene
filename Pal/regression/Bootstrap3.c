#include "pal.h"
#include "pal_regression.h"

void preload_func1(void);
void preload_func2(void);

int main(int argc, char** argv, char** envp) {
    /* check if the program is loaded */
    pal_printf("User Program Started\n");

    preload_func1();
    preload_func2();

    return 0;
}
