#define _GNU_SOURCE
#include <err.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char** argv) {
    const char buf[] = "Hello world\n";
    long ret = syscall(__NR_write, 1, buf, sizeof(buf) - 1);
    if (ret < 0)
        err(EXIT_FAILURE, "write syscall");

    return 0;
}
