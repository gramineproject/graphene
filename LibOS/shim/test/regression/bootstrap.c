#include <stdio.h>
#include <string.h>

int main(int argc, const char** argv, const char** envp) {
    printf("User Program Started\n");

    printf("# of Arguments: %d\n", argc);

    for (int i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }

    /* Make sure argv strings are placed compactly in order */
    size_t sum_len = 0;
    for (int i = 0; i < argc; i++) {
        sum_len += strlen(argv[i]) + 1;
    }

    size_t chunk_len = argv[argc - 1] + strlen(argv[argc - 1]) - argv[0];
    if (sum_len != chunk_len + 1) {
        printf("argv strings are not in desirable locations\n");
        return -1;
    }

    return 0;
}
