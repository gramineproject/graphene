#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MESSAGE "hello world"
#define MESSAGE_LEN 11

int main(int argc, char** argv) {
    bool delete = false;

    int i = 1;
    if (i < argc && strcmp(argv[i], "-d") == 0) {
        delete = true;
        i++;
    }

    if (i + 1 != argc)
        errx(1, "Usage: %s [-d] path", argv[0]);

    const char* path = argv[i];

    int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0666);
    if (fd == -1)
        err(1, "open");

    if (delete) {
        if (unlink(path) == -1)
            err(1, "unlink");
    }

    const char* message = MESSAGE;
    size_t pos = 0;
    do {
        ssize_t ret = write(fd, &message[pos], MESSAGE_LEN - pos);
        if (ret < 0)
            err(1, "write");
        pos += ret;
    } while (pos < MESSAGE_LEN);

    if (fsync(fd) == -1)
        err(1, "fsync");

    pid_t pid = fork();
    if (pid < 0)
        err(1, "fork");

    if (pid == 0) {
        if (lseek(fd, 0, SEEK_SET) == -1)
            err(1, "seek");

        char buf[MESSAGE_LEN];
        pos = 0;
        do {
            ssize_t ret = read(fd, &buf[pos], MESSAGE_LEN - pos);
            if (ret < 0)
                err(1, "write");
            if (ret == 0)
                errx(1, "unexpected EOF");
            pos += ret;
        } while (pos < MESSAGE_LEN);

        if (memcmp(message, buf, MESSAGE_LEN) != 0)
            errx(1, "wrong message");
    } else {
        int status;
        if (waitpid(pid, &status, 0) == -1)
            err(1, "waitpid");
        if (!WIFEXITED(status))
            errx(1, "child not exited");
        if (WEXITSTATUS(status) != 0)
            errx(1, "unexpected exit status: %d", WEXITSTATUS(status));

        if (!delete) {
            if (unlink(path) == -1)
                err(1, "unlink");
        }

        printf("TEST OK\n");
    }
    return 0;
}
