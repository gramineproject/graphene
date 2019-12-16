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

#define TEST_DIR        "tmp"
#define TEST_FILE       "__testfile__"

typedef enum
{
    false = 0,
    true = 1
}bool;

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

ssize_t rw_file(int fd, char* buf, size_t bytes, bool write_flag) {
    ssize_t rv = 0;
    ssize_t ret;

    while (bytes > rv) {
        if (write_flag)
            ret = write(fd, buf + rv, bytes - rv);
        else
            ret = read(fd, buf + rv, bytes - rv);

        if (ret >= 0) {
            rv += ret;
        } else {
            if (errno == EAGAIN || errno == EINTR) {
                continue;
            } else {
                printf("%s failed:%s\n", write_flag ? "write" : "read", strerror(errno));
                perror("");
                break;
            }
        }
    }

    return rv;
}

int main(int argc, const char** argv) {
    char buf[BUF_LENGTH];
    int rv = 0;
    ssize_t bytes;
    int fd = 0;

    unlink(TEST_DIR"/"TEST_FILE);

    /* test readdir: should not find a file that we just deleted */
    if (find_file(TEST_DIR, TEST_FILE)) {
        printf("The file %s was unexpectedly found\n", TEST_FILE);
        rv = -1;
        goto out;
    }

    fd = open(TEST_DIR"/"TEST_FILE, O_CREAT | O_RDWR | O_TRUNC, 0660);
    if (fd < 0) {
        perror("open failed");
        return -1;
    }

    if (!find_file(TEST_DIR, TEST_FILE)) {
        printf("The file %s was not found\n", TEST_FILE);
        rv = -1;
        goto out;
    }

    /* test file size: write a file of type != FILEBUF_MAP */
    bytes = rw_file(fd, buf, BUF_LENGTH, true);
    assert(bytes == BUF_LENGTH);

    lseek(fd, 0, SEEK_SET);
    bytes = rw_file(fd, buf, 1, true);
    assert(bytes == 1);

    lseek(fd, 4096, SEEK_SET);
    bytes = write(fd, buf, BUF_LENGTH);
    bytes = rw_file(fd, buf, BUF_LENGTH, true);
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
    bytes = rw_file(fd, buf, BUF_LENGTH, false);
    if (bytes != BUF_LENGTH) {
        printf("read length\n");
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
