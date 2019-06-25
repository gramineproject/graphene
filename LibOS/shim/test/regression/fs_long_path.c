#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define FILENAME_MAX_LENGTH 255
#define PATH "tmp/"
#define MSG "Hello World"

int main(int argc, char** argv) {
    char filename[FILENAME_MAX_LENGTH];
    memset(filename, 'a', sizeof(filename));
    filename[FILENAME_MAX_LENGTH-1] = '\0';

    char filepath[sizeof(PATH) + sizeof(filename)];
    strcpy(filepath, PATH);
    strcat(filepath, filename);

    printf("filepath = %s (len = %lu)\n", filepath, strlen(filepath));

    /* sanity check: try fopening dir in write mode (must fail) */
    errno = 0;
    FILE* fp = fopen(PATH, "w");
    if (fp != NULL || errno != EISDIR) {
        perror("(sanity check) fopen of dir with write access did not fail");
        return 1;
    }

    /* write to file */
    fp = fopen(filepath, "w");
    if (fp == NULL) {
        perror("fopen failed");
        return 1;
    }

    int ret = fwrite(MSG, sizeof(char), sizeof(MSG), fp);
    if (ret != sizeof(MSG)) {
        perror("fwrite failed");
        return 1;
    }

    fclose(fp);

    /* read from same file */
    fp = fopen(filepath, "r");
    if (fp == NULL) {
        perror("fopen failed");
        return 1;
    }

    char buf[256];
    ret = fread(buf, sizeof(char), sizeof(buf), fp);
    if (ret != sizeof(MSG)) {
        perror("fread failed");
        return 1;
    }

    fclose(fp);

    printf("Succesfully read from file: %s\n", buf);

    return 0;
}

