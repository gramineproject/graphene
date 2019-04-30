#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/time.h>
#include <errno.h>

int main (int argc, const char** argv) {
    int myfutex = 0;
    int ret;

    struct timespec t = {
        .tv_sec = 1,
        .tv_nsec = 0
    };

    puts("invoke futex syscall with 1-second timeout");
    ret = syscall(SYS_futex, &myfutex, FUTEX_WAIT, 0, &t, NULL, 0);
    if (ret == -1 && errno == ETIMEDOUT) {
        puts("futex correctly timed out");
    }

    return 0;
}
