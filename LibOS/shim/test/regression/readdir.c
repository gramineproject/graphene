#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define TEST_DIR        "tmp"
#define TEST_FILE       "__testfile__"

/* return true if file_name exists, otherwise false */
bool find_file(char* dir_name, char* file_name) {
    bool found = false;
    DIR* dir = opendir(dir_name);
    if (dir == NULL) {
        perror("opendir failed");
        return found;
    }

    errno = 0;
    struct dirent* dent = NULL;
    while (1) {
        dent = readdir(dir);
        if (dent == NULL) {
            if (errno == 0)
                break;
            perror("readdir failed");
            goto out;
        }

        if (strncmp(file_name, dent->d_name, strlen(file_name)) == 0) {
            found = true;
            break;
        }
    }

out:
    closedir(dir);
    return found;
}

int main(int argc, const char** argv) {
    int rv = 0;
    int fd = 0;

    unlink(TEST_DIR"/"TEST_FILE);

    /* test readdir: should not find a file that we just deleted */
    if (find_file(TEST_DIR, TEST_FILE)) {
        fprintf(stderr, "The file %s was unexpectedly found\n", TEST_FILE);
        rv = -1;
        goto out;
    }

    fd = open(TEST_DIR"/"TEST_FILE, O_CREAT | O_RDWR | O_TRUNC, 0660);
    if (fd < 0) {
        perror("open failed");
        return -1;
    }

    if (!find_file(TEST_DIR, TEST_FILE)) {
        fprintf(stderr, "The file %s was not found\n", TEST_FILE);
        rv = -1;
        goto out;
    }

    printf("test completed successfully\n");

out:
    if (fd)
        close(fd);

    unlink(TEST_DIR"/"TEST_FILE);
    return rv;
}
