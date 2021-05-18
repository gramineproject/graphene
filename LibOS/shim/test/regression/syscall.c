#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>

int main(int argc, char** argv) {
    const char buf[] = "Hello world\n";
    syscall(__NR_write, 1, buf, sizeof(buf) - 1);
    return 0;
}
