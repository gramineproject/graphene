#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BUF_LENGTH      4096

#define TEST_DIR        "/tmp"
#define TEST_FILE       "__testfile__"

/* return 1 if file_name exists, otherwise 0 */
int find_file(char* dir_name, char* file_name)
{
    int found = 0;
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
            found = 1;
            break;
        }
    }

out:
    closedir(dir);
    return found;
}

int main(int argc, const char** argv) {
    char buf[BUF_LENGTH];
    int rv = 0;
    int bytes;
    int fd = 0;

    unlink(TEST_DIR"/"TEST_FILE);

    /* test readdir: Find a newly created file */
    if (find_file(TEST_DIR, TEST_FILE) == 1) {
        printf("failed\n");
        rv = -1;
        goto out;
    }

    fd = open(TEST_DIR"/"TEST_FILE, O_CREAT | O_RDWR | O_TRUNC, 0660);
    if (fd < 0) {
        perror("open failed");
        return -1;
    }

    if (find_file(TEST_DIR, TEST_FILE) == 0) {
        printf("The file %s was not found\n", TEST_FILE);
        rv = -1;
        goto out;
    }

    /* test file size: write a file of type != FILEBUF_MAP */
    bytes = write(fd, buf, BUF_LENGTH);
    assert(bytes == BUF_LENGTH);

    lseek(fd, 0, SEEK_SET);
    bytes = write(fd, buf, 1);
    assert(bytes == 1);

    lseek(fd, 4096, SEEK_SET);
    bytes = write(fd, buf, BUF_LENGTH);
    assert(bytes == BUF_LENGTH);

    close(fd);
    fd = open(TEST_DIR"/"TEST_FILE, O_RDONLY);
    if (fd < 0) {
        perror("open failed");
        return -1;
    }

    /* reopen file, the file size should be 4096 + BUF_LENGTH,
       try read BUF_LENGTH bytes from position 4096 */
    lseek(fd, 4096, SEEK_SET);
    bytes = read(fd, buf, BUF_LENGTH);
    if (bytes != BUF_LENGTH) {
        printf("read failed\n");
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
