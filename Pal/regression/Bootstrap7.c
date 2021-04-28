#include "pal.h"
#include "pal_regression.h"

int main(int argc, char** argv, char** envp) {
    /* check if the programriables in the manifest should appear  is loaded */
    pal_printf("User Program Started\n");

    /* check control block */
    /* print all environmental variables */
    /* environmental variables in Manifest should appear */
    for (int i = 0; envp[i]; i++) {
        pal_printf("%s\n", envp[i]);
    }

    return 0;
}
