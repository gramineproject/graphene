#include <stdio.h>

int main(int argc, const char** argv, const char** envp) {
    printf("User Program Started\n");

    printf("# of Arguments: %d\n", argc);

    for (int i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }

    return 0;
}
