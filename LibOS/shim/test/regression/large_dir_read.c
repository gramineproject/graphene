#define _GNU_SOURCE
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

unsigned int FILES_NO = 10000;

int main(int argc, char *argv[]) {
    int fd = 0, ret = 0;
    char name[0x10] = { 0 };
    DIR* dir = NULL;
    struct dirent* x = NULL;
    unsigned long i, count = 0;
    char* tmp_name = NULL;
    char* old_wd = NULL;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argc != 2 && argc != 3) {
        fprintf(stderr, "Usage: %s tmp_folder_name [files_count]\n", argv[0]);
        return 1;
    }

    tmp_name = argv[1];

    if (argc > 2) {
        FILES_NO = atol(argv[2]);
    }

    if ((old_wd = get_current_dir_name()) == NULL) {
        err(1, "getcwd");
    }

    if (mkdir(tmp_name, S_IRWXU | S_IRWXG | S_IRWXO) < 0 || chdir(tmp_name) < 0) {
        err(1, "mkdir & chdr");
    }

    for (i = 0; i < FILES_NO; ++i) {
        sprintf(name, "%010lu", i);
        fd = open(name, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO);
        if (fd < 0) {
            fprintf(stderr, "cannot create file %lu\n", i);
            ret = 1;
            goto cleanup;
        }
        if (close(fd) < 0) {
            fprintf(stderr, "close failed with: %s\n", strerror(errno));
        }
    }

    dir = opendir(".");
    if (!dir) {
        fputs("cannot open \".\"", stderr);
        ret = 1;
        goto cleanup;
    }

    while (1) {
        errno = 0;
        x = readdir(dir);
        if (!x) {
            if (errno != 0) {
                fprintf(stderr, "error: readdir: %s\n", strerror(errno));
                ret = 1;
                goto cleanup;
            } else {
                break;
            }
        }
        count++;
    }

    printf("count: %lu\n", count);

cleanup:
    if (dir) {
        closedir(dir);
    }

    for (i = 0; i < FILES_NO; ++i) {
        sprintf(name, "%010lu", i);
        unlink(name);
    }

    if (chdir(old_wd) < 0) {
        fprintf(stderr, "could not change directory to original (%s): %s\n", old_wd, strerror(errno));
    }
    free(old_wd);

    rmdir(tmp_name);

    return ret;
}
