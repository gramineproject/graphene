#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PATH                "file_check_policy_testfile"

static inline int run_file_check_policy(void) {
//    setbuf(stdout, NULL);
//    setbuf(stderr, NULL);

    FILE* fp = fopen(PATH, "r");
    if (!fp) {
        perror("fopen failed");
        return 1;
    }

    int reti = fclose(fp);
    if (reti) {
        perror("fclose failed");
        return 1;
    }

    printf("file_check_policy succeeded\n");

    return 0;
}
