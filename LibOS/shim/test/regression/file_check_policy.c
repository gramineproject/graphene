#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s read|append <filename>\n", argv[0]);
        return 1;
    }

    /* we use append instead of write simply to not overwrite the file */
    FILE* fp = fopen(argv[2], argv[1][0] == 'r' ? "r" : "a");
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
