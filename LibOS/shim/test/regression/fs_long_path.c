#include <string.h>
#include <stdio.h>
#include <stdlib.h>

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

    /* write to file */
    FILE* fp = fopen(filepath, "w");
    if (fp == NULL) {
        perror("fopen failed");
        return 1;
    }

    int ret = fwrite(MSG, sizeof(char), sizeof(MSG), fp);
    if (ret != sizeof(MSG)) {
        return 1;
        perror("fwrite failed");
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
        return 1;
        perror("fread failed");
    }

    fclose(fp);

    printf("Succesfully read from file: %s\n", buf);

    return 0;
}

