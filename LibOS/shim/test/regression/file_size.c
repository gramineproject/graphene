#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define BUF_LENGTH      4096

#define TEST_DIR        "tmp"
#define TEST_FILE       "__testfile__"

ssize_t rw_file(int fd, char* buf, size_t bytes, bool write_flag) {
    ssize_t rv = 0;
    ssize_t ret;

    while (bytes > rv) {
        errno = 0;
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
                fprintf(stderr, "%s failed:%s\n", write_flag ? "write" : "read", strerror(errno));
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

    fd = open(TEST_DIR"/"TEST_FILE, O_CREAT | O_RDWR | O_TRUNC, 0660);
    if (fd < 0) {
        perror("open failed");
        return -1;
    }

    /* test file size: write a file of type != FILEBUF_MAP */
    bytes = rw_file(fd, buf, BUF_LENGTH, true);
    assert(bytes == BUF_LENGTH);

    lseek(fd, 0, SEEK_SET);
    bytes = rw_file(fd, buf, 1, true);
    assert(bytes == 1);

    lseek(fd, 4096, SEEK_SET);
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
        fprintf(stderr, "read length(%zd) is not expected(%d)\n", bytes, BUF_LENGTH);
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
