#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(int argc, const char** argv, const char** envp) {
    printf("User Program Started\n");

    printf("# of arguments: %d\n", argc);

    for (int i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }

    puts("");
    size_t envs_cnt = 0;
    for (size_t i = 0; envp[i]; i++)
        envs_cnt++;
    printf("# of envs: %zu\n", envs_cnt);
    for (size_t i = 0; envp[i]; i++) {
        printf("envp[%zu] = %s\n", i, envp[i]);
    }

    /* Make sure argv strings follow the compact encoding where (1) all strings
       are located adjacently and (2) in increasing order. */
    size_t sum_len = 0;
    for (int i = 0; i < argc; i++) {
        sum_len += strlen(argv[i]) + 1;
    }

    size_t chunk_len = argv[argc - 1] + strlen(argv[argc - 1]) - argv[0];
    if (sum_len != chunk_len + 1) {
        printf("argv strings are not adjacent or not in increasing order\n");
        return 1;
    }

    return 0;
}
