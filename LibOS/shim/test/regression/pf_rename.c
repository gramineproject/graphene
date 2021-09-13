/* Protected file renaming. */

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PF_FOO_PATH "pftmp/foo.txt"
#define PF_BAR_PATH "pftmp/bar.txt"
#define BUF_SIZE    15

int main(void) {
    char buf[BUF_SIZE];
    char input_text[] = "Hello, world!";
    int fd = open(PF_FOO_PATH, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0)
        err(1, "File creation failed");

    size_t size = strlen(input_text) + 1;
    char* str = input_text;
    while (size > 0) {
        ssize_t n = write(fd, str, size);
        if (n == -1) {
            close(fd);
            err(1, "Writing to file failed");
        }
        assert(n <= size);
        size -= n;
        str += n;
    }

    int ret = close(fd);
    if (ret < 0)
        err(1, "Cannot close file");

    ret = rename(PF_FOO_PATH, PF_BAR_PATH);
    if (ret < 0) {
        err(1, "Rename failed");
    }

    /* Open the renamed file */
    fd = open(PF_BAR_PATH, O_RDONLY);
    if (fd < 0)
        err(1, "Cannot open renamed file");

    size_t pos = 0;
    do {
        ssize_t n = read(fd, &buf[pos], BUF_SIZE - pos);
        if (n == -1)
            err(1, "Reading from renamed file failed");
        if (n == 0) {
            if (size > 0) {
                warnx("Read less bytes than expected");
                return -1;
            }
            break;
        }
        pos += n;
    } while (pos < BUF_SIZE);

    ret = close(fd);
    if (ret < 0)
        err(1, "Cannot close file");

    buf[sizeof(buf) - 1] = '\0';

    /* Check if the renamed file's contents are same as original text */
    if (strncmp(input_text, buf, sizeof(input_text)))
        err(1, "Renamed file content mismatching");

    printf("TEST OK\n");
    return 0;
}
