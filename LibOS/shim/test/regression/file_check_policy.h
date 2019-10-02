#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline int run_file_check_policy_test(int argc, char** argv) {
//    setbuf(stdout, NULL);
//    setbuf(stderr, NULL);

    if (argc != 2) {
        fprintf(stderr, "Usage: %s file_check_policy_testfile\n", argv[0]);
        return 1;
    }

    FILE* fp = fopen(argv[1], "r");
    if (!fp) {
        perror("fopen failed");
        return 2;
    }

    int reti = fclose(fp);
    if (reti) {
        perror("fclose failed");
        return 3;
    }

    printf("file_check_policy succeeded\n");

    return 0;
}
